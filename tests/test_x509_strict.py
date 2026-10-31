"""X509_STRICT (SPEC §10, D13): the one flag it decides on the upstream TLS context, the
startup refusal, what health and the log say, and the hint a failed verification gets.

The non-conforming authority is a trustme CA re-signed with its own key and contents, its
Basic Constraints and Key Usage not marked critical, though RFC 5280 requires Basic
Constraints to be critical on a CA certificate. Certificates are generated per run and never
committed; requests go through the client a deployment builds, against TLS servers on loopback.
"""

import json
import os
import socket
import ssl
import subprocess
import sys

import httpcore
import httpx
import pytest
import trustme
from conftest import (
    API_KEY,
    NO_UPSTREAM,
    assert_reached,
    assert_refused,
    leaf_from,
    pem_file,
    proxy_for,
    upstream,
)
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from fastapi.testclient import TestClient

from vt_proxy.config import Settings
from vt_proxy.main import create_app
from vt_proxy.tls import STRICT_ONLY, strict_hint

pytestmark = pytest.mark.usefixtures("isolated_client_env")

REFUSED = "VT unreachable or timed out (ConnectError)"
HINTED = (
    "VT unreachable or timed out (ConnectError); "
    "TLS: Basic Constraints of CA cert not marked critical, see X509_STRICT"
)


def non_conforming(ca: trustme.CA) -> trustme.CA:
    """`ca` re-signed with its own key and contents, Basic Constraints and Key Usage not
    critical."""
    cert = x509.load_pem_x509_certificate(ca.cert_pem.bytes())
    key = serialization.load_pem_private_key(ca.private_key_pem.bytes(), password=None)
    builder = (
        x509.CertificateBuilder()
        .subject_name(cert.subject)
        .issuer_name(cert.issuer)
        .public_key(cert.public_key())
        .serial_number(cert.serial_number)
        .not_valid_before(cert.not_valid_before_utc)
        .not_valid_after(cert.not_valid_after_utc)
    )
    for extension in cert.extensions:
        relaxed = isinstance(extension.value, x509.BasicConstraints | x509.KeyUsage)
        builder = builder.add_extension(extension.value, extension.critical and not relaxed)
    resigned = builder.sign(key, cert.signature_hash_algorithm)
    return trustme.CA.from_pem(
        resigned.public_bytes(serialization.Encoding.PEM), ca.private_key_pem.bytes()
    )


def log_lines(stdout: str, event: str) -> list[dict]:
    lines = [json.loads(line) for line in stdout.splitlines() if line.startswith("{")]
    return [line for line in lines if line["event"] == event]


# --- trust under the flag (X1–X5, X9) --------------------------------------------------


def test_the_default_refuses_a_non_conforming_authority_with_a_hint(tmp_path, capsys):
    ca = non_conforming(trustme.CA())
    ca_file = pem_file(tmp_path / "ca.pem", ca.cert_pem)
    with upstream(leaf_from(ca)) as url, proxy_for(url, ca_file) as client:
        assert assert_refused(client) == HINTED
    [line] = log_lines(capsys.readouterr().out, "error")
    assert line["message"] == HINTED  # the error line carries the same text


def test_false_admits_the_non_conforming_authority(tmp_path):
    ca = non_conforming(trustme.CA())
    ca_file = pem_file(tmp_path / "ca.pem", ca.cert_pem)
    with upstream(leaf_from(ca)) as url, proxy_for(url, ca_file, x509_strict="false") as client:
        assert_reached(client)


@pytest.mark.parametrize("value", ["true", "false"])
def test_an_authority_in_neither_set_is_refused_without_a_hint(tmp_path, value):
    ca_file = pem_file(tmp_path / "ca.pem", non_conforming(trustme.CA()).cert_pem)
    with upstream(leaf_from(trustme.CA())) as url, proxy_for(url, ca_file, value) as client:
        assert assert_refused(client) == REFUSED  # verification stays on


def test_the_flag_acts_on_the_clients_own_default_trust_too(tmp_path, monkeypatch):
    ca = non_conforming(trustme.CA())
    # no CA_FILE: the client's own default set, selected by its own variable
    monkeypatch.setenv("SSL_CERT_FILE", pem_file(tmp_path / "bundle.pem", ca.cert_pem))
    with upstream(leaf_from(ca)) as url:
        with proxy_for(url, x509_strict="false") as client:
            assert_reached(client)
        with proxy_for(url) as client:
            assert assert_refused(client) == HINTED


@pytest.mark.parametrize("value", ["true", "false"])
def test_both_values_admit_a_conforming_authority(tmp_path, value):
    ca = trustme.CA()
    ca_file = pem_file(tmp_path / "ca.pem", ca.cert_pem)
    with upstream(leaf_from(ca)) as url, proxy_for(url, ca_file, value) as client:
        assert_reached(client)


def test_a_refused_connection_keeps_its_message():
    with socket.socket() as probe:  # a loopback port nothing listens on
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    with proxy_for(f"https://127.0.0.1:{port}/api/v3") as client:
        assert assert_refused(client) == REFUSED


# --- the setting: refusals, health and the startup line (X6, X7) -----------------------


def refusal(**settings: str) -> str:
    """The one line create_app ends the process with, for these settings."""
    with pytest.raises(SystemExit) as exit_info:
        create_app(settings=Settings(vt_api_key=API_KEY, _env_file=None, **settings))
    line = exit_info.value.code
    assert isinstance(line, str)
    assert API_KEY not in line
    return line


def test_a_value_other_than_true_or_false_refuses_the_start():
    assert refusal(x509_strict="maybe") == "X509_STRICT: expected true or false: 'maybe'"


NOT_BOOLEAN = ["0", "1", "yes", "no", "on", "off", " ", "true\nfalse"]


@pytest.mark.parametrize("value", NOT_BOOLEAN, ids=[repr(value) for value in NOT_BOOLEAN])
def test_only_true_and_false_are_values(value):
    line = refusal(x509_strict=value)
    assert line == f"X509_STRICT: expected true or false: {value!r}"
    assert "\n" not in line  # repr keeps the line whole


def test_x509_strict_is_checked_before_ca_file_is_read(tmp_path):
    line = refusal(x509_strict="maybe", ca_file=str(tmp_path / "missing.pem"))
    assert line == "X509_STRICT: expected true or false: 'maybe'"


def test_the_refusal_is_the_only_output_of_the_real_entrypoint(tmp_path):
    env = {**os.environ, "VT_API_KEY": API_KEY, "X509_STRICT": "0"}
    result = subprocess.run(
        [sys.executable, "-m", "uvicorn", "--factory", "vt_proxy.main:create_app"],
        cwd=tmp_path,  # no .env here: only this environment reaches the settings
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 1
    assert result.stdout == ""
    assert result.stderr == "X509_STRICT: expected true or false: '0'\n"


SPELLINGS = [
    (None, True),
    ("", True),
    ("true", True),
    ("TRUE", True),
    ("false", False),
    ("FALSE", False),
    (" False ", False),
]


@pytest.mark.parametrize(("value", "strict"), SPELLINGS)
def test_health_says_what_the_context_carries_and_false_logs_one_warning(value, strict, capsys):
    with proxy_for(NO_UPSTREAM, x509_strict=value) as client:
        assert client.get("/v1/health").json()["x509_strict"] is strict
    warnings = log_lines(capsys.readouterr().out, "x509_strict_disabled")
    assert len(warnings) == (0 if strict else 1)


def test_the_warning_is_a_bare_line_after_the_ca_file_line(tmp_path, capsys):
    path = pem_file(tmp_path / "ca.pem", trustme.CA().cert_pem)
    with proxy_for(NO_UPSTREAM, path, x509_strict="false") as client:
        body = client.get("/v1/health").json()
    assert list(body) == ["status", "name", "version", "extra_ca", "x509_strict"]
    lines = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert [line["event"] for line in lines] == ["ca_file_loaded", "x509_strict_disabled"]
    del lines[1]["ts"]
    assert lines[1] == {"level": "WARNING", "event": "x509_strict_disabled"}


# --- recognising the failures only the flag causes (X10) -------------------------------


def failed_verification(code: int) -> httpx.ConnectError:
    """A failed verification chained the way httpx and httpcore chain it: httpcore's pool
    re-raises `from None`, so the verify error sits on __context__."""
    verify_error = ssl.SSLCertVerificationError(1, "certificate verify failed")
    verify_error.verify_code = code
    inner = httpcore.ConnectError(str(verify_error))
    inner.__context__ = verify_error
    inner.__suppress_context__ = True
    outer = httpx.ConnectError(str(inner))
    outer.__cause__ = inner
    return outer


@pytest.mark.parametrize("code", sorted(STRICT_ONLY))
def test_each_failure_only_the_flag_causes_gets_the_hint(code):
    hint = f"; TLS: {STRICT_ONLY[code]}, see X509_STRICT"
    assert strict_hint(failed_verification(code)) == hint


@pytest.mark.parametrize("code", [20, 62, 79, 94])
def test_other_failures_get_none(code):
    # an unknown issuer, a hostname mismatch; 79 and 94 fail without the flag too
    assert strict_hint(failed_verification(code)) == ""


def test_without_a_verify_error_the_text_is_recognised():
    message = (
        "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: "
        "Missing Authority Key Identifier (_ssl.c:1035)"
    )
    hint = "; TLS: Missing Authority Key Identifier, see X509_STRICT"
    assert strict_hint(httpx.ConnectError(message)) == hint


def test_an_error_that_is_no_failed_verification_gets_none():
    assert strict_hint(httpx.ConnectError("[Errno 111] Connection refused")) == ""


@pytest.mark.parametrize(("value", "message"), [("true", HINTED), ("false", REFUSED)])
def test_only_a_context_with_the_flag_gives_the_hint(value, message):
    def handler(request: httpx.Request) -> httpx.Response:
        raise failed_verification(89)

    settings = Settings(
        vt_api_key=API_KEY, vt_base_url="https://vt.mock", x509_strict=value, _env_file=None
    )
    app = create_app(settings=settings, transport=httpx.MockTransport(handler))
    with TestClient(app, raise_server_exceptions=False) as client:
        assert assert_refused(client) == message

"""CA_FILE (SPEC §10): extra CA trust for TLS with the upstream, the startup refusals, and
what health and the log say about it.

Certificates are generated per run (trustme) and never committed. TLS servers listen on
loopback only, so the suite stays offline, and every request goes through the client a
deployment builds, not a mocked transport.
"""

import json
import os
import re
import ssl
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

import certifi
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

from vt_proxy.ca import CAFileError, load_ca_file
from vt_proxy.config import Settings
from vt_proxy.main import create_app

pytestmark = pytest.mark.usefixtures("isolated_client_env")


def startup_lines(stdout: str) -> list[dict]:
    lines = [json.loads(line) for line in stdout.splitlines() if line.startswith("{")]
    return [line for line in lines if line["event"] == "ca_file_loaded"]


# --- trust (T1–T4) -------------------------------------------------------------


def test_without_ca_file_an_unknown_authority_is_refused():
    with upstream(leaf_from(trustme.CA())) as url, proxy_for(url) as client:
        assert_refused(client)


def test_an_authority_from_ca_file_is_trusted(tmp_path):
    ca = trustme.CA()
    ca_file = pem_file(tmp_path / "ca.pem", ca.cert_pem)
    with upstream(leaf_from(ca)) as url, proxy_for(url, ca_file) as client:
        assert_reached(client)


def test_an_authority_in_neither_set_is_still_refused(tmp_path):
    ca_file = pem_file(tmp_path / "ca.pem", trustme.CA().cert_pem)
    with upstream(leaf_from(trustme.CA())) as url, proxy_for(url, ca_file) as client:
        assert_refused(client)


def test_ca_file_adds_to_the_default_trust_instead_of_replacing_it(tmp_path, monkeypatch):
    a, b, c = trustme.CA(), trustme.CA(), trustme.CA()
    # the client's own default set, selected by its own variable: authority A
    monkeypatch.setenv("SSL_CERT_FILE", pem_file(tmp_path / "a.pem", a.cert_pem))
    ca_file = pem_file(tmp_path / "b.pem", b.cert_pem)
    for ca, check in ((a, assert_reached), (b, assert_reached), (c, assert_refused)):
        with upstream(leaf_from(ca)) as url, proxy_for(url, ca_file) as client:
            check(client)


# --- refusals (T5, T9) ---------------------------------------------------------


def refusal(ca_file: str) -> str:
    """The one line create_app ends the process with, for this CA_FILE."""
    settings = Settings(vt_api_key=API_KEY, ca_file=ca_file, _env_file=None)
    with pytest.raises(SystemExit) as exit_info:
        create_app(settings=settings)
    line = exit_info.value.code
    assert isinstance(line, str)
    assert API_KEY not in line
    return line


def test_a_missing_file_refuses_the_start(tmp_path):
    path = tmp_path / "missing.pem"
    assert refusal(str(path)) == f"CA_FILE: no such file: {path}"


def test_a_path_through_a_regular_file_is_a_missing_file(tmp_path):
    (tmp_path / "plain").write_text("not a directory")
    path = tmp_path / "plain" / "ca.pem"
    assert refusal(str(path)) == f"CA_FILE: no such file: {path}"


def test_a_value_of_only_whitespace_is_a_path_not_an_empty_value():
    assert refusal(" ") == "CA_FILE: no such file:  "


def test_a_directory_refuses_the_start(tmp_path):
    assert refusal(str(tmp_path)) == f"CA_FILE: not a regular file: {tmp_path}"


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads a file whatever its mode")
def test_an_unreadable_file_refuses_the_start(tmp_path):
    path = pem_file(tmp_path / "ca.pem", trustme.CA().cert_pem)
    Path(path).chmod(0)
    assert refusal(path) == f"CA_FILE: cannot be read (Permission denied): {path}"


def _corrupt(pem: bytes) -> bytes:
    lines = pem.splitlines(keepends=True)
    lines[1] = b"!!!!" + lines[1][4:]  # the first base64 line of the block
    return b"".join(lines)


NOT_LOADABLE: dict[str, Callable[[], bytes]] = {
    "empty": lambda: b"",
    "text only": lambda: b"no certificate here\n",
    "a private key only": lambda: leaf_from(trustme.CA()).private_key_pem.bytes(),
    "DER": lambda: ssl.PEM_cert_to_DER_cert(trustme.CA().cert_pem.bytes().decode()),
    "a corrupt block after a good one": lambda: (
        (pem := trustme.CA().cert_pem.bytes()) + _corrupt(pem)
    ),
}


@pytest.mark.parametrize("content", NOT_LOADABLE, ids=list(NOT_LOADABLE))
def test_a_file_without_a_loadable_certificate_refuses_the_start(tmp_path, content):
    path = tmp_path / "ca.pem"
    path.write_bytes(NOT_LOADABLE[content]())
    line = refusal(str(path))
    # the reason in between is the loader's own text, which is not pinned here
    assert line.startswith("CA_FILE: no certificate could be loaded (")
    assert line.endswith(f"): {path}")


def test_the_refusal_is_the_only_output_of_the_real_entrypoint(tmp_path):
    missing = tmp_path / "missing.pem"
    env = {**os.environ, "VT_API_KEY": API_KEY, "CA_FILE": str(missing)}
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
    assert result.stderr == f"CA_FILE: no such file: {missing}\n"


# --- health and the startup line (T6, T8, T10) ---------------------------------


def test_without_ca_file_health_says_false_and_no_line_is_logged(capsys):
    with proxy_for(NO_UPSTREAM) as client:
        assert client.get("/v1/health").json()["extra_ca"] is False
    assert startup_lines(capsys.readouterr().out) == []


def test_an_empty_ca_file_is_absent(capsys):
    with proxy_for(NO_UPSTREAM, ca_file="") as client:
        assert client.get("/v1/health").json()["extra_ca"] is False
    assert startup_lines(capsys.readouterr().out) == []


def test_with_ca_file_health_says_true_and_one_line_counts_the_certificates(tmp_path, capsys):
    path = pem_file(tmp_path / "ca.pem", trustme.CA().cert_pem, trustme.CA().cert_pem)
    with proxy_for(NO_UPSTREAM, path) as client:
        body = client.get("/v1/health").json()
    assert body == {
        "status": "ok",
        "name": "vt-proxy",
        "version": body["version"],
        "extra_ca": True,
        "x509_strict": True,
    }
    [line] = startup_lines(capsys.readouterr().out)
    del line["ts"]
    assert line == {"level": "INFO", "event": "ca_file_loaded", "path": path, "certificates": 2}


# --- the count (T12) -------------------------------------------------------------


def test_a_leaf_alone_counts_and_pins_its_server(tmp_path, capsys):
    leaf = leaf_from(trustme.CA())
    path = pem_file(tmp_path / "leaf.pem", leaf.cert_chain_pems[0])
    with upstream(leaf) as url, proxy_for(url, path) as client:
        assert_reached(client)  # partial-chain verification: the leaf anchors itself
    [line] = startup_lines(capsys.readouterr().out)
    assert line["certificates"] == 1


def test_a_root_the_default_set_already_holds_still_counts(tmp_path, capsys):
    bundle = Path(certifi.where()).read_text()
    root = re.search(r"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----\n", bundle, re.S)
    path = tmp_path / "public-root.pem"
    path.write_text(root.group(0))
    with proxy_for(NO_UPSTREAM, str(path)):
        pass
    [line] = startup_lines(capsys.readouterr().out)
    assert line["certificates"] == 1


# --- reading: text outside the PEM blocks never decides (Z3) ---------------------


def _byte_inside(pem: bytes) -> bytes:
    lines = pem.splitlines(keepends=True)
    lines[1] = lines[1][:10] + "ż".encode() + lines[1][10:]
    return b"".join(lines)


READING: dict[str, tuple[Callable[[], bytes], int | None]] = {
    "UTF-8 text before the block": (
        lambda: "Wystawca: Spółka\n".encode() + trustme.CA().cert_pem.bytes(),
        1,
    ),
    "a UTF-8 BOM before the block": (
        lambda: b"\xef\xbb\xbf" + trustme.CA().cert_pem.bytes(),
        1,
    ),
    "UTF-8 text between two blocks": (
        lambda: (
            trustme.CA().cert_pem.bytes() + "— next —\n".encode() + trustme.CA().cert_pem.bytes()
        ),
        2,
    ),
    "CRLF line endings": (
        lambda: trustme.CA().cert_pem.bytes().replace(b"\n", b"\r\n"),
        1,
    ),
    "a non-ASCII byte inside a block": (
        lambda: _byte_inside(trustme.CA().cert_pem.bytes()),
        None,
    ),
}


def count_by_service(path: Path) -> int | None:
    try:
        return load_ca_file(str(path))[1]
    except CAFileError:
        return None


def count_by_openssl_file_loader(path: Path) -> int | None:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    try:
        context.load_verify_locations(cafile=path)
    except (ssl.SSLError, ValueError):
        return None
    return context.cert_store_stats()["x509"] or None


@pytest.mark.parametrize("case", READING, ids=list(READING))
def test_reading_agrees_with_openssls_own_file_loader(tmp_path, case):
    make, expected = READING[case]
    path = tmp_path / "ca.pem"
    path.write_bytes(make())
    assert count_by_service(path) == expected
    assert count_by_openssl_file_loader(path) == expected

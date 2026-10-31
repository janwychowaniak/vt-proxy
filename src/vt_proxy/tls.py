"""The TLS context the service verifies the upstream with (SPEC §10, D12, D13).

It is httpx's own default context, read from the environment as httpx reads it, plus the
certificates of CA_FILE. X509_STRICT decides one flag on it, ssl.VERIFY_X509_STRICT: the
RFC 5280 conformance checks Python 3.13 turns on by default. Verification is never off.
"""

import ssl
from collections.abc import Iterator

import httpx

# The verify errors OpenSSL raises only under the flag, its RFC 5280 checks (OpenSSL 3.5,
# check_extensions in x509_vfy.c), with OpenSSL's own texts. Not 79 (invalid CA certificate)
# or 94 (explicit EC parameters): OpenSSL raises those without the flag too, so clearing it
# would not cure them.
STRICT_ONLY: dict[int, str] = {
    78: "cert info signature and signature algorithm mismatch",
    80: "Path length invalid for non-CA cert",
    81: "Path length given without key usage keyCertSign",
    82: "Key usage keyCertSign invalid for non-CA cert",
    83: "Issuer name empty",
    84: "Subject name empty",
    85: "Missing Authority Key Identifier",
    86: "Missing Subject Key Identifier",
    87: "Empty Subject Alternative Name extension",
    88: "Subject empty and Subject Alt Name extension not critical",
    89: "Basic Constraints of CA cert not marked critical",
    90: "Authority Key Identifier marked critical",
    91: "Subject Key Identifier marked critical",
    92: "CA cert does not include key usage extension",
    93: "Using cert extension requires at least X509v3",
}


class X509StrictError(Exception):
    """X509_STRICT is neither true nor false; the message is the one line the refusal prints."""


def parse_x509_strict(value: str | None) -> bool:
    """X509_STRICT as a boolean: true or false in any case, with whitespace around it trimmed.

    Unset or empty means true. Anything else is refused, with the value as given in repr, so
    that a newline or an escape character in it cannot split or forge a log line.
    """
    if not value:
        return True
    word = value.strip().lower()
    if word not in ("true", "false"):
        raise X509StrictError(f"X509_STRICT: expected true or false: {value!r}")
    return word == "true"


def upstream_context(pem: str | None, strict: bool) -> ssl.SSLContext:
    """httpx's default context, plus pem when given, and the flag set last.

    Nothing else on the context changes: the other flags, the verify mode, hostname
    checking and the minimum version stay as httpx sets them.
    """
    context = httpx.create_ssl_context()
    if pem is not None:
        context.load_verify_locations(cadata=pem)
    if strict:
        context.verify_flags |= ssl.VERIFY_X509_STRICT
    else:
        context.verify_flags &= ~ssl.VERIFY_X509_STRICT
    return context


def is_strict(context: ssl.SSLContext) -> bool:
    return bool(context.verify_flags & ssl.VERIFY_X509_STRICT)


def strict_hint(exc: BaseException) -> str:
    """'; TLS: <reason>, see X509_STRICT' for a failure only the flag causes, else ''."""
    reason = _strict_only_reason(exc)
    return "" if reason is None else f"; TLS: {reason}, see X509_STRICT"


def _chain(exc: BaseException) -> Iterator[BaseException]:
    # httpcore's connection pool re-raises `from None`: that clears __cause__, while the
    # verify error stays on __context__
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        yield current
        current = current.__cause__ or current.__context__


def _strict_only_reason(exc: BaseException) -> str | None:
    chain = list(_chain(exc))
    for link in chain:
        if isinstance(link, ssl.SSLCertVerificationError):
            return STRICT_ONLY.get(getattr(link, "verify_code", None))
    # no verify error on the chain: recognise the reason by its text
    for link in chain:
        for reason in STRICT_ONLY.values():
            if reason in str(link):
                return reason
    return None

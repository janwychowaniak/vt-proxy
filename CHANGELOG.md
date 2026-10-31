# Changelog

The release notes are the annotated tag messages. This file carries the same
notes where they can be read without git, together with the image digest each
version was published under, its image Id (configuration digest) and the Python
it runs, and corrections to them as errata.

**A tag is never pushed again, not even to fix its message.** Pushing it runs
the release again and can publish the same version under a different digest,
which breaks the one property a pinned deployment stands on. A wrong line in a
tag message is corrected here instead, as an erratum that says what the tag
claims and what is true.

The image Id is what a host compares after `docker load` of a release file. On
Docker's default `overlay2` image store, it is the digest of the image's
configuration, which the archive carries byte for byte (see the README).

## 0.3.0 — (pending: the date of the tag)

`ghcr.io/janwychowaniak/vt-proxy@sha256:` (pending: from the release workflow's
step summary)

Image Id (configuration digest) `sha256:` (pending), after a pull and after
`docker load` of the release file alike. Python (pending).

An opt-out of Python's strict X.509 checks, for an authority that cannot
conform.

- X509_STRICT (new, optional, default true): with false, the service clears
  ssl.VERIFY_X509_STRICT, and only that flag, on the TLS context it verifies
  VirusTotal with, directly or through a proxy tunnel; the TLS of an https://
  proxy endpoint itself keeps its default checks. Verification stays on: the
  chain is still verified against the trusted authorities, CA_FILE included,
  and the hostname is still checked. The values are true and false, in any
  letter case, with surrounding whitespace ignored; unset or empty means true,
  and any other value refuses the start with one line naming X509_STRICT.
- GET /v1/health gains "x509_strict", the state the TLS context carries; a
  start with false logs one x509_strict_disabled warning.
- A failed verification that only the strict checks cause still answers 504
  UPSTREAM_TIMEOUT; while the checks are on, its message now names OpenSSL's
  reason and points at X509_STRICT.

Unset, the checks are those 0.2.0 ran; only the message of a failure they
cause grows. Unchanged: the /v1 endpoints, the response envelope, the error
codes, CA_FILE, the proxy variables, and the non-root,
classic-builder-compatible image.

## 0.2.0 — 2026-10-29

`ghcr.io/janwychowaniak/vt-proxy@sha256:e5d6593a78d54455ae44c8539d577c40baaee888fb70ac5b71df0905c18b5a5b`

Image Id (configuration digest)
`sha256:fbf11f1cd2aebaa2716b1d5666f1f80e01583b9449eb934fb0bc92d469ccb775`, after
a pull and after `docker load` of the release file alike. Python 3.13.18.

Erratum: the release workflow's step summary shows
`sha256:e5d6593a78d54455ae44c8539d577c40baaee888fb70ac5b71df0905c18b5a5b` as the
image Id, because the runner's Docker uses the containerd image store, where
`docker image inspect` reports the manifest digest.

Extra CA trust without a derived image, and the image as a release file.

- CA_FILE (new, optional): a PEM file of certificate authorities trusted in
  addition to the default ones for TLS with VirusTotal, directly or through a
  proxy tunnel; the TLS of an https:// proxy endpoint itself keeps the
  default trust. Read once at startup; a missing, unreadable or
  certificate-less file refuses the start with one line naming CA_FILE.
  Verification is never switched off.
- GET /v1/health gains "extra_ca": true when CA_FILE is loaded.
- compose.ca.yml mounts the file and sets the variable; the derived-image
  recipe is gone from the documentation.
- Every release now carries the published image as vt-proxy-<version>.tar.gz,
  saved by its full tag, with its .sha256; CHANGELOG.md records each version's
  digest and image Id (configuration digest).
- Base image: the runtime stays on Debian 13 (trixie), as in 0.1.0, now pinned
  by name (python:3.13-slim-trixie); the build stage moved from Debian 12 to 13.
  Python 3.13 as shipped by python:3.13-slim-trixie at build time (0.1.0:
  3.13.14).
- compose.yaml now names the published image,
  ghcr.io/janwychowaniak/vt-proxy:latest, instead of a local vt-proxy:0.1.0.

Unchanged: the /v1 lookup and search endpoints, the response envelope, the
error contract (a failed TLS verification is still 504 UPSTREAM_TIMEOUT), the
proxy variables, and the non-root, classic-builder-compatible image.

## 0.1.0 — 2026-07-30

`ghcr.io/janwychowaniak/vt-proxy@sha256:2c97f0d56a451ff602e131c62f33bf2ff4312f6ff423cc08ea23a5b620c3eefb`,
the digest the `0.1.0` tag resolved to in the registry on 2026-10-29, when this
entry was written.

Image Id (configuration digest)
`sha256:579f4fd7fd9857c4ee3cd4ec8839b63f0ea3baacbfe4dd8acfdda1282d93dbbe`,
obtained by pulling that digest. Created 2026-07-30T21:46:07Z; Python 3.13.14.

The first release: reputation lookups for file hashes, IP addresses, domains
and URLs, and a name→hash sample search, against the VirusTotal API v3, in one
JSON envelope with an explicit flag-score. Its tag is lightweight and has no
release on GitHub, so this entry is its only record.

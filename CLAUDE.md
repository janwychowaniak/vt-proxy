# CLAUDE.md

Guidance for AI-assisted work in this repository.

## What this is

vt-proxy is a small, self-hosted HTTP service that sits between local
applications and the VirusTotal API v3. It answers read-only reputation
questions about IOCs (file hashes, IP addresses, domains/FQDNs, URLs) and
supports a name→hash sample lookup, returning VT's knowledge in a stable,
analyst-friendly JSON envelope with an explicit flag-score (how many vendors
flagged the IOC).

- Functional specification: `docs/SPEC.md` — the source of truth.
- Research notes and captured VT v3 responses: `docs/research/`.

## Hard constraints (never violate)

- **Read-only proxy.** The service only queries VT. It never submits, uploads,
  or modifies anything on the VT side.
- **No downloads, ever.** The service must never download files/samples from VT
  nor serve binary payloads in any direction. All traffic is JSON. This is a
  deliberate, non-negotiable security boundary.
- **Localhost-only, no auth by design.** Intended for callers on the same
  trusted machine; the container port must be published on `127.0.0.1` only.
- **TLS verification is never switched off.** `CA_FILE` only adds certificate
  authorities to the default trust, and `X509_STRICT` relaxes RFC 5280
  conformance checks, never verification; no setting disables verification
  (`docs/SPEC.md` §10, `[D12]`, `[D13]`).
- **The VT API key lives in the environment** (`.env` locally, never
  committed). Never print, log, or copy it into fixtures, docs, or commit
  messages. Gitleaks hooks + CI enforce secret hygiene; activate hooks once
  per clone: `git config core.hooksPath .githooks`. The add-on rules in
  `.gitleaks.toml` are prefix-anchored on purpose — the built-in generic rule
  is not a reliable fallback; the file explains why. Measure any change to
  them against a corpus of fake keys before committing.

## Language

Everything that lands in the repository — code, comments, commit messages,
docs — is English only. In conversation, mirror the language the maintainer
uses (often Polish); that never changes the English-only rule for repo
content.

## Toolchain

- Python 3.13, fully type-hinted, modern idioms
- **uv** (`pyproject.toml` + `uv.lock`) — dependency management; uv-first workflows
- FastAPI + uvicorn; pydantic v2 + pydantic-settings (12-Factor env config); httpx (async)
- `ioc-typing` (pinned) — IOC type classification for the omni endpoint
- ruff (lint + format), pytest
- Docker + Compose for build/run; logs go to stdout/stderr only (no log
  files, no log volumes — rotation is Docker's job)

## Development

- `uv sync` — full environment (interpreter pinned by `.python-version`)
- `uv run pytest` — the offline suite; needs no VT key and no network **by
  design** (CI relies on this — keep it that way)
- `uv run ruff check` / `uv run ruff format` — lint / format
- `VT_LIVE_TESTS=1 uv run pytest tests/test_live_smoke.py` — optional live
  smoke tests; require a real key in `.env`
- Local run:
  `uv run uvicorn --factory vt_proxy.main:create_app --host 127.0.0.1 --port 11000`

## Release

Every public step (push, tag) needs the maintainer's explicit word.

1. **Release commit** on `main`:
   - bump `version` in `pyproject.toml`, then run `uv lock`;
   - move the README's `docker pull` example to the new version;
   - add the `CHANGELOG.md` entry: the notes, with placeholders for the date,
     the digest, the image Id (configuration digest) and the Python.

   CI must be green on it.
2. **Tag:** an **annotated** `v<version>`, whose message is `vt-proxy
   <version>`, a blank line, then that entry's notes.
   - Build the message from the entry; never retype it. The notes are the
     entry's paragraphs without the digest line, the image Id paragraph and
     errata. Both `v0.2.0` and `v0.3.0` follow this rule byte for byte.
   - Show the full text to the maintainer before tagging.
   - Create the tag with `git tag -a --cleanup=verbatim -F <file>`.
   - Compare the created tag's message with the text before pushing it: the
     message part of `git cat-file tag` must equal the file byte for byte.
     Do not compare against `git tag --format='%(contents)'`, which prints an
     extra newline.

   `release.yml` refuses a lightweight tag, or a tag that does not match
   `pyproject.toml`, before anything is built.
3. **The workflow:**
   - `publish` runs the suite on the tagged commit, builds with the classic
     builder and pushes `ghcr.io/janwychowaniak/vt-proxy:<version>` and
     `:latest` (public, linked to this repo).
   - Its step summary records the digest, the image Id (configuration digest)
     and the Python. The Id is read from the pushed manifest, because on the
     runner's containerd image store `docker image inspect .Id` is the
     manifest digest.
   - `archive` pulls by digest and runs `.github/scripts/archive-image.sh`,
     which checks the archive's configuration digest against the record and
     proves the load.
   - It then creates the GitHub Release from the tag message, with
     `vt-proxy-<version>.tar.gz` and its `.sha256`, and checks that the
     release notes equal the tag message.
   - If `archive` fails, re-run that job alone.
4. **Afterwards:** read the run's log, then commit the date, digest, image Id
   and Python into the `CHANGELOG.md` entry on `main`.

**A tag is never pushed again, not even to fix its message.** Doing so re-runs
the release and can publish the same version under another digest; a wrong
line is corrected in `CHANGELOG.md` as an erratum.

The release path runs only on tags. A change to `release.yml` or
`archive-image.sh` is checked locally as far as it goes, then by reading the
next release's log.

## Key decisions

- VirusTotal API **v3** only; a paid API key is assumed.
- Flag-score = `last_analysis_stats.malicious` — exactly the number analysts
  see in the VT GUI.
- "IOC unknown to VT" (VT 404 `NotFoundError`) is **not** an error for this
  service — it maps to a normal `known: false` response. Real failures
  (quota, auth, timeouts, upstream validation) map to meaningful HTTP codes,
  passing VT's v3 error semantics through where sensible.
- All lookup endpoints are read-only in semantics regardless of the HTTP
  method chosen for transport (see `docs/SPEC.md`).
- Tests run offline against captured fixtures. The `CA_FILE` and
  `X509_STRICT` tests run against TLS servers on loopback, with certificates
  generated per run (`trustme` and `cryptography`, both dev-only dependencies).
  Optional live smoke tests are gated behind an env flag and never run in CI,
  so a change to anything they call (such as `VTClient`) must be checked by
  hand.

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
- **The VT API key lives in the environment** (`.env` locally, never
  committed). Never print, log, or copy it into fixtures, docs, or commit
  messages. Gitleaks hooks + CI enforce secret hygiene; activate hooks once
  per clone: `git config core.hooksPath .githooks`.

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

Bump `version` in `pyproject.toml`, commit, tag `v<version>`, push the tag.
The release workflow hard-fails on a tag/pyproject version mismatch, then
builds and publishes `ghcr.io/janwychowaniak/vt-proxy:<version>` + `:latest`
(public, linked to this repo). CI must be green on main before tagging.

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
- Tests run offline against captured fixtures; optional live smoke tests are
  gated behind an env flag.

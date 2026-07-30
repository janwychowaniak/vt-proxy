# vt-proxy

[![ci](https://github.com/janwychowaniak/vt-proxy/actions/workflows/ci.yml/badge.svg)](https://github.com/janwychowaniak/vt-proxy/actions/workflows/ci.yml)
[![gitleaks](https://github.com/janwychowaniak/vt-proxy/actions/workflows/gitleaks.yml/badge.svg)](https://github.com/janwychowaniak/vt-proxy/actions/workflows/gitleaks.yml)

A small, self-hosted, **read-only** HTTP proxy in front of the
[VirusTotal API v3](https://docs.virustotal.com/reference/overview). It answers
IOC reputation questions — file hashes, IP addresses, domains, URLs — in one
stable, analyst-friendly JSON envelope, with the number analysts actually look
at (how many vendors flagged the IOC) extracted into an explicit score.

Built for local callers (SOAR pipelines, scripts, other services) sharing one
paid VT API key on a trusted machine.

## Why

Raw VT v3 is a fine API with a few ergonomic sharp edges when all you want is
"how bad is this thing":

- four endpoints and vocabularies for four IOC types — here: one envelope,
  plus an omni endpoint that detects the artifact type for you (via
  [ioc-typing](https://github.com/janwychowaniak/ioc-typing));
- URLs must be addressed by unpadded-base64 identifiers — absorbed here;
- "VT doesn't know this IOC" is a 404 *error* — here it's a normal
  `known: false` *answer*;
- a malformed hash is **also** a 404, indistinguishable from "unknown" — here
  garbage input is rejected up front (422) and never reaches VT;
- the vendor flag-count sits nested in `last_analysis_stats` — here it's
  `verdict.score`, while the full raw VT report is still passed through
  verbatim, so no information is ever lost.

## Hard boundaries (by design)

- **Read-only.** The service only ever issues GETs against VT. Nothing is
  submitted, uploaded, rescanned or modified.
- **No binary payloads.** It never downloads files from VT and serves nothing
  but JSON. There is no endpoint that could return a sample.
- **Localhost-only, no auth.** Intended for callers on the same trusted
  machine; the compose file publishes the port strictly on `127.0.0.1`.
  Do not widen that binding — the API is deliberately unauthenticated.
- **Key hygiene.** The VT API key lives in the environment only; it is never
  logged and structurally cannot end up in an image layer (whitelist
  `.dockerignore`). The repo itself is guarded by layered
  [gitleaks](https://github.com/gitleaks/gitleaks) scanning (hooks + CI).

## Quickstart (Docker)

```bash
cp .env.example .env        # put your VT_API_KEY inside
docker compose up -d        # legacy docker-compose works too
curl http://127.0.0.1:11000/v1/health
```

Prebuilt images are published on version tags:
`docker pull ghcr.io/janwychowaniak/vt-proxy:0.1.0` (`latest` tracks the
newest release).

## API

All lookup endpoints are `POST` with a JSON body — read-only in semantics,
POST in transport, so URLs and free-text fields travel safely (the same
pattern as Elasticsearch `_search`).

| Endpoint | Method | Purpose |
|---|---|---|
| `/v1/score/file` | POST | file reputation, by md5/sha1/sha256 |
| `/v1/score/ip` | POST | IP reputation (IPv4 or IPv6) |
| `/v1/score/domain` | POST | domain / FQDN reputation |
| `/v1/score/url` | POST | URL reputation |
| `/v1/score` | POST | **omni** — artifact type auto-detected, then as above |
| `/v1/search/name` | POST | name→hash sample lookup (VT Intelligence search) |
| `/v1/health` | GET | liveness; no VT call |

Interactive OpenAPI docs: `http://127.0.0.1:11000/docs`.

### Score lookup

```bash
curl -s -X POST http://127.0.0.1:11000/v1/score \
  -H "Content-Type: application/json" \
  -d '{"artifact": "44d88612fea8a8f36de82e1278abb02f", "positives_thresh": 5, "msg": "case-4711"}'
```

```jsonc
{
  "query":   { "artifact": "44d88612fea8a8f36de82e1278abb02f", "type": "file",
               "positives_thresh": 5, "msg": "case-4711" },
  "known":   true,
  "verdict": {
    "score": 65,                    // = last_analysis_stats.malicious, the VT-GUI number
    "thresh_gte": true,             // score >= positives_thresh (inclusive)
    "stats": { "malicious": 65, "suspicious": 0, "undetected": 3, "harmless": 0,
               "timeout": 0, "confirmed-timeout": 0, "failure": 1, "type-unsupported": 6 }
  },
  "report":  {                      // the VT v3 `data` object, verbatim
    "id": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
    "type": "file",
    "links": { "...": "..." },
    "attributes": { "...": "full VT knowledge, untouched (abridged here)" }
  }
}
```

Three strictly separated layers: what was asked (`query`), what this service
computed (`verdict`), what VT said (`report`). An IOC unknown to VT is a
**success**, not an error:

```json
{ "query": { "...": "..." }, "known": false, "verdict": null, "report": null }
```

`positives_thresh` defaults to `1` ("at least one vendor flagged it"); `msg`
is an optional free-text tag echoed back and written to the log line — handy
for correlating with your calling system's case IDs.

### Name → hash search

Finds recent samples by file name (requires a VT key with Intelligence
search). Values below are a real capture, abridged:

```bash
curl -s -X POST http://127.0.0.1:11000/v1/search/name \
  -H "Content-Type: application/json" \
  -d '{"name": "eicar.com", "days_ago": 14, "limit": 3}'
```

```jsonc
{
  "query": { "name": "eicar.com", "days_ago": 14, "limit": 3, "msg": null },
  "known": true,
  "total_hits": 62,
  "matches": [                       // newest first (server-side ordering)
    {
      "sha256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
      "sha1": "3395856ce81f2b7382dee72602f798b642f14140",
      "md5": "44d88612fea8a8f36de82e1278abb02f",
      "size": 68,
      "type_description": "Powershell",
      "meaningful_name": "eicar.com-25389",
      "first_submission_date": "2006-05-22T12:42:02Z",
      "last_submission_date": "2026-07-29T16:53:21Z",
      "score": 65,
      "stats": { "malicious": 65, "...": "..." }
    }
  ]
}
```

Matches are trimmed projections — a full report is one `/v1/score/file` call
away with the returned hash. Want just "the hash for this name"? Take
`matches[0].sha256`.

### Errors

One envelope for everything non-2xx:

```json
{ "error": { "code": "UPSTREAM_QUOTA", "message": "VT quota or rate limit exceeded",
             "upstream": { "status": 429, "code": "QuotaExceededError", "message": "..." } } }
```

| Situation | HTTP | `error.code` |
|---|---|---|
| malformed request body | 422 | `VALIDATION_ERROR` |
| unrecognized/unsupported artifact, type mismatch | 422 | `INVALID_ARTIFACT` |
| VT quota / rate limit (Retry-After passed through) | 429 | `UPSTREAM_QUOTA` |
| this service's VT key rejected | 502 | `UPSTREAM_AUTH` |
| VT broken or answered out of contract | 502 | `UPSTREAM_ERROR` / `UPSTREAM_SCHEMA` |
| timeout — noticed by us or reported by VT | 504 | `UPSTREAM_TIMEOUT` |
| IOC unknown to VT | **200** | not an error: `known: false` |

The full contract lives in [`docs/SPEC.md`](docs/SPEC.md) — the source of
truth — grounded in live-probed API behavior documented in
[`docs/research/NOTES.md`](docs/research/NOTES.md), whose captured responses
double as this repo's offline test fixtures.

## Configuration

Environment variables (12-Factor; `.env` supported, see
[`.env.example`](.env.example)):

| Variable | Required | Default | Meaning |
|---|---|---|---|
| `VT_API_KEY` | **yes** | — | VirusTotal API key (paid tier assumed) |
| `VT_BASE_URL` | no | `https://www.virustotal.com/api/v3` | override for tests/mocks |
| `VT_TIMEOUT` | no | `30` | per-VT-request timeout, seconds |
| `LOG_LEVEL` | no | `INFO` | log verbosity |
| `VT_PROXY_PORT` | no | `11000` | compose only: host port on `127.0.0.1` |
| `HTTPS_PROXY` / `NO_PROXY` | no | — | standard egress-proxy variables, honored as-is |

Logs are JSON lines on stdout — `docker compose logs -f` to watch, rotation
capped in `compose.yaml`. No log files, no volumes.

## Running without Docker

```bash
uv sync --no-dev
uv run uvicorn --factory vt_proxy.main:create_app --host 127.0.0.1 --port 11000
```

## Development

```bash
uv sync                                   # full env (Python 3.13, deps, dev tools)
uv run pytest                             # offline suite — no network, no key needed
uv run ruff check && uv run ruff format   # lint + format
VT_LIVE_TESTS=1 uv run pytest tests/test_live_smoke.py   # optional, needs a real key
git config core.hooksPath .githooks       # once per clone: gitleaks commit/push guards
```

Tests run entirely against captured VT responses
(`docs/research/fixtures/`) through a mocked transport; CI never needs a key.

## Deploying behind a corporate proxy

Egress proxy is runtime configuration, not a code concern — set
`HTTPS_PROXY`/`NO_PROXY` in the container environment. If your proxy
intercepts TLS, add its CA in a thin derived image and point Python's trust
at the system store:

```dockerfile
FROM ghcr.io/janwychowaniak/vt-proxy:0.1.0
USER root
COPY corp-ca.crt /usr/local/share/ca-certificates/
RUN update-ca-certificates
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
USER app
```

## License

[MIT](LICENSE)

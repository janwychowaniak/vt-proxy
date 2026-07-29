# vt-proxy — functional specification

**Status: APPROVED (2026-07-29).** This file is the source of truth for
implementation. Design decisions are marked `[D#]` inline and recorded in
[§13](#13-decision-record); observed VT behavior they build on is documented
in [`research/NOTES.md`](research/NOTES.md).

## 1. Purpose

vt-proxy is a small, self-hosted HTTP service that answers read-only IOC
reputation questions by querying the VirusTotal API v3 with a single paid API
key. It exists to give local applications (SOAR pipelines, scripts, other
services) a **simpler and more stable contract than raw VT**:

- one uniform request/response envelope for all IOC types,
- an explicit **flag-score** — the number of vendors flagging the IOC, the
  same number analysts see in the VT GUI,
- "VT doesn't know it" as a normal answer instead of an error,
- input validation that distinguishes garbage from unknown,
- a name→hash sample search without touching VT Intelligence quirks directly.

## 2. Hard boundaries (from CLAUDE.md, restated as API guarantees)

- **Read-only**: the service performs only GET requests against VT. Nothing is
  ever submitted, uploaded, rescanned, commented, or modified.
- **No binary payloads**: the service never downloads files from VT and never
  serves anything but JSON. There is no endpoint that could return a sample.
- **Localhost-only, no auth**: deployment publishes the port on `127.0.0.1`
  exclusively. The API itself is unauthenticated by design.
- **Key hygiene**: the VT API key is read from the environment and never
  appears in responses or logs.

## 3. API conventions

- All lookup endpoints are **`POST` with a JSON body**, despite being
  read-only. Rationale: URL and free-text fields (`artifact`, `msg`) travel
  safely in a body; VT itself gave up on URLs-in-paths (base64url ids); one
  calling convention for every endpoint; consumers are programs, not
  browsers. Read-only semantics are guaranteed by this spec, not by the verb.
  `[D1]`
- All paths carry a **`/v1` prefix** (cheap insurance for a public project).
  `[D2]`
- No trailing slashes. `Content-Type: application/json`, UTF-8.
- Unknown fields in request bodies are **rejected** (`422`) — catches typos
  like `positives_tresh` instead of silently ignoring them.
- Interactive OpenAPI docs (`/docs`, `/openapi.json`) stay enabled — the
  service is localhost-only.

## 4. Endpoints overview

| Endpoint | Purpose |
|---|---|
| `POST /v1/score/file` | reputation of a file by hash (md5/sha1/sha256) |
| `POST /v1/score/ip` | reputation of an IPv4 address |
| `POST /v1/score/domain` | reputation of a domain / FQDN |
| `POST /v1/score/url` | reputation of a URL |
| `POST /v1/score` | **omni**: auto-detect artifact type, then behave as the matching endpoint `[D3]` |
| `POST /v1/search/name` | name→hash lookup via VT Intelligence search |
| `GET /v1/health` | liveness: static `ok` + app name/version; no VT call |

Upstream mapping: `/files/{hash}`, `/ip_addresses/{ip}`, `/domains/{domain}`,
`/urls/{base64url(url) without padding}`, `/intelligence/search`.

## 5. Score endpoints — request

Identical body for all five — one uniform `artifact` field regardless of
IOC type:

```json
{
  "artifact": "44d88612fea8a8f36de82e1278abb02f",   // required, non-empty
  "positives_thresh": 5,                             // optional int >= 0, default 1  [D4]
  "msg": "case-4711"                                 // optional, logged for correlation
}
```

- `artifact` is validated with **ioc-typing** before any VT call. Typed
  endpoints require the matching type; mismatch or unrecognizable input is a
  `422`, *not* a VT roundtrip.
- `positives_thresh` is inclusive: `thresh_gte = (score >= positives_thresh)`.
  Default `1` = "at least one vendor flagged it".
- `msg` is echoed in the response and written to the log line; it never
  influences behavior.

## 6. Score endpoints — response envelope

Three layers, strictly separated: what was asked (`query`), what we computed
(`verdict`), what VT said verbatim (`report`).

**Known IOC** (real captured numbers — EICAR):

```json
{
  "query": {
    "artifact": "44d88612fea8a8f36de82e1278abb02f",
    "type": "file",
    "positives_thresh": 5,
    "msg": "case-4711"
  },
  "known": true,
  "verdict": {
    "score": 65,
    "thresh_gte": true,
    "stats": {
      "malicious": 65, "suspicious": 0, "undetected": 3, "harmless": 0,
      "timeout": 0, "confirmed-timeout": 0, "failure": 1, "type-unsupported": 6
    }
  },
  "report": {
    "id": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
    "type": "file",
    "links": { "self": "https://www.virustotal.com/api/v3/files/275a02..." },
    "attributes": { "…": "full VT attributes, passed through verbatim" }
  }
}
```

**Unknown IOC** (VT 404 → our HTTP 200):

```json
{
  "query": { "artifact": "0f1e2d…eeff0", "type": "file", "positives_thresh": 5, "msg": null },
  "known": false,
  "verdict": null,
  "report": null
}
```

Envelope rules:

- All four top-level keys are always present.
- `query.type` is the resolved type (`file | ip | domain | url`) — declared by
  the endpoint or auto-detected by omni.
- `verdict.score` = `report.attributes.last_analysis_stats.malicious`.
- `verdict.stats` duplicates `last_analysis_stats` for caller convenience —
  the primary consumables sit in one shallow place; deliberate redundancy.
  `[D5]`
- `report` is the VT v3 `data` object **verbatim** (`id`, `type`, `links`,
  `attributes`): no filtering, no renaming, no date conversion. VT's raw
  knowledge, our computed layer, never mixed.

## 7. Omni (`POST /v1/score`)

1. Classify `artifact` with ioc-typing.
2. Type determined → dispatch internally to the matching typed logic; the
   response is byte-for-byte what the typed endpoint would return (with
   `query.type` filled in).
3. Type undetermined → `422 INVALID_ARTIFACT`. VT is not consulted — a
   caller error is not the same as VT ignorance. `[D6]`

Hash note: ioc-typing reports `hash`; the envelope and endpoint naming use
`file` (the VT object the hash addresses).

## 8. Name→hash search (`POST /v1/search/name`)

Request:

```json
{
  "name": "eicar.com",     // required, non-empty; double quotes forbidden -> 422
  "days_ago": 30,           // optional int >= 1, default 30
  "limit": 10,              // optional int 1..40, default 10
  "msg": "case-4711"        // optional
}
```

- VT query: `name:"<name>" ls:<today - days_ago>+` (last-submission recency
  window). The `name` is embedded in a VT query string — hence the hard ban
  on `"` inside it (query-injection guard); any other character passes
  through literally.
- Results ordered **newest first** (server-side ordering by submission date if
  the `order` parameter verifies at implementation time — research open
  question #1 — otherwise sorted by us within the fetched page).

Response:

```json
{
  "query": { "name": "eicar.com", "days_ago": 30, "limit": 10, "msg": null },
  "known": true,
  "total_hits": 166,
  "matches": [
    {
      "sha256": "f4041df12ec3d79722af2cf64a1dbce9de928b773c61e11aaa9359e7fdbb6ac0",
      "sha1": "…",
      "md5": "6a9f6c15ac2b8f80a60c0103539c9ebd",
      "size": 68,
      "type_description": "Shell script",
      "meaningful_name": "CEPlus.sh",
      "first_submission_date": "2026-04-28T14:08:51Z",
      "last_submission_date": "2026-04-28T14:08:51Z",
      "score": 56,
      "stats": { "malicious": 56, "…": "…" }
    }
  ]
}
```

- `matches` are **trimmed projections**, not full VT objects (a full file
  object is 20–45 KB; ten of them would be a quarter-megabyte answer to
  "what's the hash"). The projection fields are exactly those listed above.
  Full detail is one `/v1/score/file` call away with the returned hash. `[D7]`
- Projection dates are converted to ISO-8601 UTC (we own these fields; raw VT
  epochs remain available via the follow-up score call).
- Zero matches → `known: false`, `matches: []`, `total_hits: 0`, HTTP 200.
- Callers that just want "the hash for this name" take `matches[0].sha256`.

## 9. Error contract

One error body shape for **everything** non-2xx, including schema validation
(FastAPI's default 422 body is overridden for uniformity):

```json
{
  "error": {
    "code": "UPSTREAM_QUOTA",
    "message": "VT quota exceeded",
    "upstream": { "status": 429, "code": "QuotaExceededError", "message": "…" }
  }
}
```

`upstream` is present only when VT itself answered with an error object.

| Situation | HTTP | `error.code` |
|---|---|---|
| malformed request body / unknown fields | 422 | `VALIDATION_ERROR` |
| artifact fails ioc-typing / wrong type for endpoint / undetermined omni / forbidden `"` in name | 422 | `INVALID_ARTIFACT` |
| VT 401/403 — key wrong or tier-insufficient (server misconfig, not caller's fault) | 502 | `UPSTREAM_AUTH` `[D8]` |
| VT 429 (quota / rate limit) | 429 | `UPSTREAM_QUOTA` (Retry-After passed through if present) |
| VT 5xx or transient errors | 502 | `UPSTREAM_ERROR` |
| VT unreachable / connect error / timeout | 504 | `UPSTREAM_TIMEOUT` |
| VT 200 but response fails our minimal structure validation | 502 | `UPSTREAM_SCHEMA` |
| unexpected internal failure | 500 | `INTERNAL` |

**Never an error**: VT 404 `NotFoundError` on a well-formed artifact → HTTP
200, `known: false` (§6) or empty `matches` (§8).

Minimal structure we validate on VT 200s: `data.id`, `data.type`,
`data.attributes.last_analysis_stats` (for search: per-item), everything else
opaque — mirrors the research finding that this is the entire contract we
rely on.

## 10. Configuration (12-Factor III)

Environment variables, loaded and validated at startup via pydantic-settings
(`.env` supported for local dev; missing required values = refuse to start):

| Variable | Required | Default | Meaning |
|---|---|---|---|
| `VT_API_KEY` | **yes** | — | VirusTotal API key |
| `VT_BASE_URL` | no | `https://www.virustotal.com/api/v3` | override for tests/mocks |
| `VT_TIMEOUT` | no | `30` | per-VT-request timeout, seconds |
| `LOG_LEVEL` | no | `INFO` | log verbosity |

Listen address/port are deployment concerns (uvicorn/compose), not app config.

## 11. Logging

- stdout/stderr only; no files, no rotation logic in-app.
- One structured line per handled request: endpoint, resolved type, artifact,
  `known`, `score`, `positives_thresh`, `msg`, VT HTTP status, duration.
- Errors log the mapped `error.code` plus upstream detail.
- The API key never appears in any log line (including httpx debug output).

## 12. Testing contract

- Unit/integration tests run **offline** against `docs/research/fixtures/`
  served through a mocked transport (`VT_BASE_URL` + httpx mock).
- A live smoke test suite (a handful of real calls, quota-cheap) is gated
  behind an env flag (e.g. `VT_LIVE_TESTS=1`) and never runs in CI.

## 13. Decision record

All approved by the maintainer, 2026-07-29:

- **[D1] POST-for-read everywhere.**
- **[D2] `/v1` path prefix.**
- **[D3] Omni at bare `POST /v1/score`** (over a `/v1/score/auto` variant).
- **[D4] `positives_thresh` optional, default 1.**
- **[D5] `verdict.stats` duplicates report data** — deliberate convenience.
- **[D6] Undetermined omni artifact → 422** — a caller error is not VT
  ignorance.
- **[D7] Search returns trimmed projections** (field list in §8) — full
  objects are one `/v1/score/file` call away.
- **[D8] VT auth failures surface as 502 `UPSTREAM_AUTH`, not 401** — a 401
  would wrongly imply the caller must authenticate.

## 14. Explicitly out of scope (v1)

- Response caching / TTL (would save quota; revisit after v1).
- Quota introspection endpoint (`/users/{id}/overall_quotas`).
- IPv6 (ioc-typing scope to verify; VT supports it — revisit on demand).
- Batch endpoints (multiple artifacts per call).
- Any write-path VT features (rescan, comments, submissions) — **permanently**
  out, per §2.

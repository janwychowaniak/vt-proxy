# VirusTotal API v3 — research notes (live probes)

Captured **2026-07-29** against `https://www.virustotal.com/api/v3` with a paid
API key. All probes are read-only GETs. Raw responses (pretty-printed,
otherwise verbatim) live in [`fixtures/`](fixtures/) — see the
[manifest](fixtures/README.md). The probe script is [`probe.sh`](probe.sh);
it reads the key from `.env` and an automated post-capture check verifies the
key appears in no artifact.

These notes feed `docs/SPEC.md`. Where something is a decision, the spec wins;
this file records what the API actually does.

---

## TL;DR for the spec

- All four IOC object types share one skeleton: `data.{id, type, links, attributes}`.
- `attributes.last_analysis_stats` is present and uniform across types —
  **the flag-score (`malicious`) is a direct field read, no calculation**.
- "VT doesn't know it" = HTTP 404 `NotFoundError` — to be translated into our
  normal `known: false` response, not an error.
- A *malformed* hash also yields 404 (not 400), so input pre-validation
  (ioc-typing) is on us if we want to distinguish "garbage in" from "unknown".
- Errors come as `{"error": {"code": "...", "message": "..."}}` + HTTP status.
- Intelligence search (name→hash) works on this key tier; cursor-paginated;
  supports server-side ordering (e.g. newest-first) via `allowed_orders`.
- All timestamps are Unix epochs (UTC).

---

## 1. Probe inventory

| Fixture | Request | HTTP |
|---|---|---|
| `file_eicar_by_md5.json` | `GET /files/44d88612fea8a8f36de82e1278abb02f` (EICAR, by md5) | 200 |
| `ip_google_dns.json` | `GET /ip_addresses/8.8.8.8` | 200 |
| `domain_example_com.json` | `GET /domains/example.com` | 200 |
| `url_example_com.json` | `GET /urls/aHR0cDovL2V4YW1wbGUuY29tLw` (`http://example.com/`) | 200 |
| `intel_search_eicar_by_name.json` | `GET /intelligence/search?query=name:"eicar.com" fs:2025-01-01+&limit=5` | 200 |
| `file_unknown_404.json` | `GET /files/<random 64-hex>` | 404 |
| `error_404_malformed_hash.json` | `GET /files/not-a-valid-hash` | 404 |
| `error_401_wrong_key.json` | `GET /files/<eicar md5>` with a bogus key | 401 |

Also captured: [`response-headers.sample.txt`](response-headers.sample.txt)
(headers of a successful lookup).

## 2. Common response shape

Every successful single-object lookup returns:

```json
{
  "data": {
    "id": "...",
    "type": "file | ip_address | domain | url",
    "links": { "self": "..." },
    "attributes": { ... }
  }
}
```

No other top-level keys. This uniformity makes one generic pydantic model for
"the minimal contract we rely on" feasible: `data.id`, `data.type`,
`data.attributes.last_analysis_stats` — everything else passes through opaquely.

## 3. `last_analysis_stats` — the flag-score source

Uniformly present. Two variants of key sets:

- **ip_address / domain / url** (5 buckets):
  `malicious, suspicious, undetected, harmless, timeout`
- **file** (8 buckets): the above plus
  `confirmed-timeout, failure, type-unsupported`
  (note: kebab-case keys — pydantic models need aliases, or keep it as a plain dict)

Captured examples:

| IOC | malicious | full stats sum |
|---|---|---|
| EICAR (file) | **65** | 75 |
| 8.8.8.8 | 0 | 91 |
| example.com | 0 | 91 |
| http://example.com/ | 0 | 92 |

Decision (already made): **our score = `last_analysis_stats.malicious`** — the
number analysts see in the VT GUI. The GUI's denominator is approximately the
sum of the buckets; whether it excludes `type-unsupported` is unverified — we
don't need it (full stats are passed through; callers can derive any ratio).

Other reputation-ish attributes present on all types, NOT used for the score
but interesting as envelope garnish someday: `reputation` (community score,
e.g. EICAR 3788, 8.8.8.8 556), `total_votes`, `threat_severity`, and for files
`popular_threat_classification`.

## 4. Identifiers and normalization

- **Files**: query by md5, sha1 or sha256 — VT normalizes: we asked by md5 and
  got `data.id` = sha256 (`275a02...651fd0f`). Attributes carry all three
  hashes (`md5`, `sha1`, `sha256`).
- **URLs**: the request identifier is `base64url(url)` **without padding**:
  ```python
  base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
  ```
  The returned `data.id` is a different, internal sha256-style URL id
  (`2a1b40...9a067`). Both identify the object; `attributes.url` carries the
  canonical URL (`http://example.com/` — trailing slash added).
- **Domains / IPs**: id is the domain/IP verbatim.

## 5. Dates

All timestamps are Unix epoch seconds (UTC), e.g.
`first_submission_date: 1777550931`. VT query modifiers (`fs:2025-01-01+`)
take ISO dates. Any date rendering for humans is our job.

## 6. Error model

Shape, consistently: HTTP status + `{"error": {"code": "...", "message": "..."}}`.

Observed live:

| Situation | HTTP | `error.code` | `error.message` |
|---|---|---|---|
| unknown hash | 404 | `NotFoundError` | `File "<hash>" not found` |
| **malformed** hash | 404 | `NotFoundError` | `Resource not found.` |
| wrong API key | 401 | `WrongCredentialsError` | `Wrong API key` |

Documented by VT but not provoked (to be handled generically):
`BadRequestError` (400), `ForbiddenError` (403), `QuotaExceededError` (429),
`TooManyRequestsError` (429), `TransientError` (503), `DeadlineExceededError` (504).

Implications:

- 404 → our `known: false`, HTTP 200. Not an error.
- Malformed input is indistinguishable from unknown on the VT side (both 404) —
  **pre-validating input with ioc-typing lets our proxy give the caller a
  cleaner contract than VT itself** (e.g. 422 "not a valid hash" vs 200 known:false).
- Everything else: pass through VT's status + error object semantics, wrapped
  in our error envelope.

## 7. Intelligence search (name→hash)

`GET /intelligence/search?query=<vt-query>&limit=N` — **works on this key tier**.

Response shape differs from single lookups — it is a collection:

```json
{
  "data":  [ { full file objects, same shape as /files/{hash} } ],
  "meta":  { "cursor": "...", "total_hits": 166, "estimated_total_hits": true,
             "days_back": 90, "allowed_orders": [ "first_submission_date",
             "last_submission_date", "positives", "times_submitted", "size",
             "unique_sources", "gti_score" ], "execution_time_s": 0.4, "st_search": true },
  "links": { "self": "...", "next": "...&cursor=..." }
}
```

- Pagination: opaque `meta.cursor` / `links.next`.
- Query `name:"eicar.com" fs:2025-01-01+` returned files whose `names` array
  contains the queried name (`meaningful_name` may differ).
- `meta.allowed_orders` suggests server-side ordering — for our
  "newest sample with this name" endpoint, ordering by
  `last_submission_date`/`first_submission_date` descending would replace any
  client-side newest-picking. **Verify exact `order` param syntax at
  implementation time.**
- `meta.days_back: 90` appeared despite `fs:` covering ~7 months — semantics
  unclear (default search window?). **Open question — test how `fs:` and
  `days_back` interact before relying on date filtering.**

## 8. Attribute inventory (captured keys per type)

Full attribute key sets as seen in fixtures, for spec/envelope reference.
Everything is passed through opaquely; we only *rely* on `last_analysis_stats`.

- **file**: `antiy_info, autostart_locations, available_tools,
  crowdsourced_ai_results, crowdsourced_ids_results, crowdsourced_ids_stats,
  crowdsourced_yara_results, downloadable, exiftool, filecondis,
  first_seen_itw_date, first_submission_date, known_distributors,
  last_analysis_date, last_analysis_results, last_analysis_stats,
  last_modification_date, last_seen_itw_date, last_submission_date, magic,
  magika, md5, meaningful_name, names, popular_threat_classification,
  reputation, saferpickle, sandbox_verdicts, sha1, sha256,
  sigma_analysis_results, sigma_analysis_stats, sigma_analysis_summary, size,
  ssdeep, tags, threat_severity, times_submitted, tlsh, total_votes, trid,
  type_description, type_extension, type_tag, type_tags, unique_sources`
- **ip_address**: `as_owner, asn, continent, country, crowdsourced_context,
  first_seen_itw_date, jarm, last_analysis_date, last_analysis_results,
  last_analysis_stats, last_https_certificate, last_https_certificate_date,
  last_modification_date, last_seen_itw_date, network, rdap,
  regional_internet_registry, reputation, tags, threat_severity, total_votes,
  whois, whois_date`
- **domain**: `categories, creation_date, crowdsourced_context,
  expiration_date, favicon, first_seen_itw_date, jarm, last_analysis_date,
  last_analysis_results, last_analysis_stats, last_dns_records,
  last_dns_records_date, last_https_certificate, last_https_certificate_date,
  last_modification_date, last_seen_itw_date, last_update_date,
  popularity_ranks, rdap, registrar, reputation, tags, threat_severity, tld,
  total_votes, whois, whois_date`
- **url**: `categories, console_messages, crowdsourced_context,
  first_seen_itw_date, first_submission_date, has_content, html_meta,
  identified_brands, javascript_variables, last_analysis_date,
  last_analysis_results, last_analysis_stats, last_final_url,
  last_http_response_code, last_http_response_content_length,
  last_http_response_content_sha256, last_http_response_cookies,
  last_http_response_cookies_extended, last_http_response_headers,
  last_modification_date, last_seen_itw_date, last_submission_date,
  main_brand, outgoing_links, proxy_country, redirection_chain, reputation,
  tags, targeted_brand, threat_names, threat_severity, times_submitted,
  title, tld, total_votes, url, user_agent, web_category`

Payload sizes observed: 20–45 KB per object (`last_analysis_results` with
~90 engines dominates), 125 KB for a 5-hit search.

## 9. Response headers

Nothing quota- or rate-limit-related in response headers (see sample). If
quota introspection is ever wanted, it's a separate endpoint
(`GET /users/{id}/overall_quotas`) — out of scope for now.

## 10. Open questions carried to implementation

1. `order` parameter syntax for intelligence search (newest-first).
2. `meta.days_back` vs `fs:` modifier interaction.
3. Shape of 429 `QuotaExceededError` (unobserved; handle generically).
4. GUI denominator formula (cosmetic only; stats are passed through anyway).

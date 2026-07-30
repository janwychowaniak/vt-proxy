# Fixtures — live VT API v3 responses

Captured 2026-07-29, supplemented 2026-07-30, by [`../probe.sh`](../probe.sh)
(read-only GETs, paid key).
Response bodies are verbatim except for pretty-printing. VT does not echo the
API key in responses, and an automated post-capture grep confirms no artifact
contains it. These files double as offline test fixtures.

| File | Request | HTTP |
|---|---|---|
| `file_eicar_by_md5.json` | `GET /files/44d88612fea8a8f36de82e1278abb02f` (EICAR by md5; note `data.id` comes back as sha256) | 200 |
| `ip_google_dns.json` | `GET /ip_addresses/8.8.8.8` | 200 |
| `ip6_google_dns.json` | `GET /ip_addresses/2001:4860:4860::8888` (IPv6; expanded form also accepted, id normalized to compressed) | 200 |
| `domain_example_com.json` | `GET /domains/example.com` | 200 |
| `url_example_com.json` | `GET /urls/aHR0cDovL2V4YW1wbGUuY29tLw` — id is `base64url("http://example.com/")` without padding | 200 |
| `intel_search_eicar_by_name.json` | `GET /intelligence/search?query=name:"eicar.com" fs:2025-01-01+&limit=5` | 200 |
| `intel_search_ls_window.json` | `GET /intelligence/search?query=name:"eicar.com" ls:2026-06-30+&limit=3` — verifies the `ls:` modifier (total_hits 124 vs 166 unfiltered) | 200 |
| `intel_search_ls_ordered.json` | as above, plus `&order=last_submission_date-` — verifies server-side newest-first ordering | 200 |
| `file_unknown_404.json` | `GET /files/<random 64-hex>` — hash unknown to VT | 404 |
| `error_404_malformed_hash.json` | `GET /files/not-a-valid-hash` — malformed input is also a 404, not a 400 | 404 |
| `error_401_wrong_key.json` | valid path, bogus key | 401 |

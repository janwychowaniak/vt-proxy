#!/usr/bin/env bash
# Live VT API v3 research probe. Run from the repo root:
#
#   bash docs/research/probe.sh
#
# Reads VT_API_KEY from ./.env (never prints it), performs READ-ONLY GETs
# only, and saves pretty-printed responses under docs/research/fixtures/.
# A post-capture check verifies the key leaked into no artifact.
set -u

FIX=docs/research/fixtures
LOG=$(mktemp); TMP=$(mktemp)
trap 'rm -f "$LOG" "$TMP"' EXIT
mkdir -p "$FIX"

# Tolerant .env parse: VAR=VAL, VAR = VAL, export VAR=VAL, quotes, CRLF
KEY=$(sed -nE 's/^[[:space:]]*(export[[:space:]]+)?VT_API_KEY[[:space:]]*=?[[:space:]]*//p' .env | head -1 | tr -d "\"' \r")
if [ -z "$KEY" ]; then echo "FATAL: could not parse VT_API_KEY from .env"; exit 1; fi
echo "parsed key length: ${#KEY}"

vt_get() {  # $1=fixture-name  $2=path-with-query  [$3=key-override]
  local name="$1" path="$2" key="${3:-$KEY}" status
  status=$(curl -sS --max-time 30 -o "$TMP" -w '%{http_code}' \
           -H "x-apikey: $key" "https://www.virustotal.com/api/v3$path")
  jq . "$TMP" > "$FIX/$name.json" 2>/dev/null || cp "$TMP" "$FIX/$name.json"
  echo "$status  $name  GET /api/v3$path" >> "$LOG"
  echo "$status  $name"
}

# --- the four canonical lookups -------------------------------------------
vt_get file_eicar_by_md5   "/files/44d88612fea8a8f36de82e1278abb02f"
vt_get ip_google_dns       "/ip_addresses/8.8.8.8"
vt_get domain_example_com  "/domains/example.com"

URLID=$(python3 -c "import base64; print(base64.urlsafe_b64encode(b'http://example.com/').decode().rstrip('='))")
vt_get url_example_com     "/urls/$URLID"

# --- name->hash lookup (VT Intelligence search) ---------------------------
IQ=$(python3 -c "import urllib.parse; print(urllib.parse.quote('name:\"eicar.com\" fs:2025-01-01+'))")
vt_get intel_search_eicar_by_name "/intelligence/search?query=$IQ&limit=5"

# --- edge/error shapes ----------------------------------------------------
vt_get file_unknown_404        "/files/0f1e2d3c4b5a69788796a5b4c3d2e1f00112233445566778899aabbccddeeff0"
vt_get error_404_malformed_hash "/files/not-a-valid-hash"
vt_get error_401_wrong_key     "/files/44d88612fea8a8f36de82e1278abb02f" \
                               "0000000000000000000000000000000000000000000000000000000000000000"

# --- response headers sample (scrub cookies just in case) -----------------
curl -sS --max-time 30 -D "$TMP" -o /dev/null \
     -H "x-apikey: $KEY" "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8"
grep -iv '^set-cookie' "$TMP" > docs/research/response-headers.sample.txt

# --- hygiene check: the key must not appear anywhere in artifacts ---------
if grep -rqF "$KEY" docs/research/; then
  echo "WARNING: KEY FOUND IN RESEARCH ARTIFACTS — DO NOT COMMIT"
else
  echo "hygiene: research artifacts clean of the key"
fi

echo "--- capture log ---"
cat "$LOG"

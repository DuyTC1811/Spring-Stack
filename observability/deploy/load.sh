#!/usr/bin/env bash
# Tạo traffic để có dữ liệu trên dashboard. GBP cố ý không hỗ trợ -> sinh lỗi 422.
set -euo pipefail
BASE=${BASE:-http://localhost:8080}
COUNT=${COUNT:-300}
CURRENCIES=(USD EUR JPY GBP)

for _ in $(seq 1 "$COUNT"); do
  ccy=${CURRENCIES[$((RANDOM % ${#CURRENCIES[@]}))]}
  body="{\"amount\": $((RANDOM % 5000 + 1)), \"currency\": \"$ccy\"}"
  ref=$(curl -s -X POST "$BASE/api/disbursements" -H 'Content-Type: application/json' -d "$body" \
        | sed -n 's/.*"reference":"\([^"]*\)".*/\1/p')
  if [[ -n "$ref" && $((RANDOM % 2)) -eq 0 ]]; then
    curl -s -o /dev/null -X POST "$BASE/api/disbursements/$ref/disburse"
  fi
  sleep 0.2
done

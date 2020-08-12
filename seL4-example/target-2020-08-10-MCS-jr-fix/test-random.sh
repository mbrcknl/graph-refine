#!/bin/bash

set -euo pipefail

# Assumes the following environment variables are set:
# - BV_SPREADSHEET_URL
# - BV_SPREADSHEET_KEY

mkdir -p logs/tmp

FUN="$(./functions-untested.sh | shuf -n1)"

if [ -z "$FUN" ]; then
  exit  1
fi

./test-function.sh "$FUN"

curl -s -S \
  -F "reporttxt=@report-$FUN.txt" \
  -F "apikey=$BV_SPREADSHEET_KEY" \
  -F "submit=Submit Query" \
  "$BV_SPREADSHEET_URL/upload.php"

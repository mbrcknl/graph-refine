#!/bin/bash

# Assumes the following environment variables are set:
# - BV_SPREADSHEET_URL
# - BV_SPREADSHEET_KEY

set -euo pipefail

FUN="$1"

if [ -z "$FUN" ]; then
  echo "usage ./test-function.sh FUNCTION_NAME"
  exit 1
fi

REPORT="report-$FUN.txt"

mkdir -p logs/tmp

script -c "python ../../graph-refine.py . trace-to:$REPORT $FUN" log-$FUN.txt

curl -s -S \
  -F "reporttxt=@$REPORT" \
  -F "apikey=$BV_SPREADSHEET_KEY" \
  -F "submit=Submit Query" \
  "$BV_SPREADSHEET_URL/upload.php"

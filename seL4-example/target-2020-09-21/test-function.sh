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

REPORT_DIR="logs/fun/$FUN"
REPORT="$REPORT_DIR/report.txt"
LOG="$REPORT_DIR/log.txt"

mkdir -p logs/tmp logs/fun

if [ ! -d logs/fun -o ! -d logs/tmp ]; then
    exit 1
fi

if ! mkdir "$REPORT_DIR"; then
    # Presumably we lost the race to start testing this function.
    exit 0
fi

script -c "python ../../graph-refine.py . trace-to:$REPORT $FUN" "$LOG"

curl -s -S \
  -F "reporttxt=@$REPORT" \
  -F "apikey=$BV_SPREADSHEET_KEY" \
  -F "submit=Submit Query" \
  "$BV_SPREADSHEET_URL/upload.php"

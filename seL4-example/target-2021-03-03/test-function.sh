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

LOCK_DIR="logs/lock/$FUN"
REPORT_DIR="logs/fun/$FUN"
REPORT="$REPORT_DIR/report.txt"
LOG="$REPORT_DIR/log.txt"

mkdir -p logs/tmp "$REPORT_DIR" logs/lock

if [ ! -d logs/tmp -o ! -d "$REPORT_DIR" -o ! -d logs/lock ]; then
  exit 1
fi

rmlock() {
  rmdir "$LOCK_DIR"
}

if ! mkdir "$LOCK_DIR"; then
  # Presumably we lost the race to start testing this function.
  exit 0
fi

trap rmlock EXIT TERM INT

exec < /dev/null > >(tee "$LOG") 2>&1
date

python2 ../../graph-refine.py . trace-to:"$REPORT" "$FUN" || true

date

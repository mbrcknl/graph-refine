#!/bin/bash

# Assumes the following environment variables are set:
# - BV_SPREADSHEET_URL

set -euo pipefail

TARGET_HASH=$(sha256sum ASMFunctions.txt | awk '{print $1}')

mkdir -p logs/lock

functions_tested () {
  curl -s -S "$BV_SPREADSHEET_URL/plain_pass.php?hash=$TARGET_HASH"
  curl -s -S "$BV_SPREADSHEET_URL/plain_fail.php?hash=$TARGET_HASH"
  ls logs/lock
}

functions_tested | sort -u

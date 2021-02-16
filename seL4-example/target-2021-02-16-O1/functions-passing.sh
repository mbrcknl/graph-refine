#!/bin/bash

# Assumes the following environment variables are set:
# - BV_SPREADSHEET_URL

set -euo pipefail

TARGET_HASH=$(sha256sum ASMFunctions.txt | awk '{print $1}')

functions_passing () {
  curl -s -S "$BV_SPREADSHEET_URL/plain_pass.php?hash=$TARGET_HASH"
}

functions_passing | sort -u

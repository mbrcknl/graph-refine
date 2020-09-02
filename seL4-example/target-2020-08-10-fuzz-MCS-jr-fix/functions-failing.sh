#!/bin/bash

# Assumes the following environment variables are set:
# - BV_SPREADSHEET_URL

set -euo pipefail

functions_failing () {
  curl -s -S "$BV_SPREADSHEET_URL/plain_fail.php"
}

functions_failing | sort -u

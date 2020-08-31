#!/bin/bash

# Assumes the following environment variables are set:
# - BV_SPREADSHEET_URL

set -euo pipefail

functions_tested () {
  curl -s -S "$BV_SPREADSHEET_URL/plain_pass.php"
  curl -s -S "$BV_SPREADSHEET_URL/plain_fail.php"
}

functions_tested | sort -u

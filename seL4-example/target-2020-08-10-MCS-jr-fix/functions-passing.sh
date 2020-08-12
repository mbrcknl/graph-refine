#!/bin/bash

# Assumes the following environment variables are set:
# - BV_SPREADSHEET_URL

set -euo pipefail

functions_passing () {
  curl -s -S "$BV_SPREADSHEET_URL/plain_pass.php"
}

functions_passing | sort -u

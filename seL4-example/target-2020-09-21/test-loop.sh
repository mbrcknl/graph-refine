#!/bin/bash

set -euo pipefail

# Assumes the following environment variables are set:
# - BV_SPREADSHEET_URL
# - BV_SPREADSHEET_KEY

while ./test-random.sh; do true; done

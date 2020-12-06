#!/bin/bash

# Assumes the following environment variables are set:
# - BV_SPREADSHEET_URL

set -euo pipefail

./functions-testing.sh | comm -23 functions-all.txt -

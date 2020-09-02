#!/bin/bash

# Assumes the following environment variables are set:
# - BV_SPREADSHEET_URL
# - BV_SPREADSHEET_KEY

set -euo pipefail

./test-function.sh $(./functions-untested.sh | shuf -n1)

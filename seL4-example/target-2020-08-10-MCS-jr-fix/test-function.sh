#!/bin/bash
set -euo pipefail
script -c "python ../../graph-refine.py . trace-to:report-$1.txt $1" log-$1.txt

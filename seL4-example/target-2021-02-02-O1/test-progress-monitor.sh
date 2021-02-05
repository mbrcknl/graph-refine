#!/bin/bash

set -euo pipefail

while true; do
  passing=$(./functions-passing.sh | wc -l)
  untested=$(./functions-untested.sh | wc -l)
  failing="$(./functions-failing.sh)"
  processing="$(ls logs/lock)"
  clear
  echo passing:
  echo $passing
  echo
  echo untested:
  echo $untested
  echo
  echo failing:
  echo "$failing"
  echo
  echo processing:
  echo "$processing"
  echo
  sleep 30
done

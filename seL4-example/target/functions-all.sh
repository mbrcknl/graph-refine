#!/bin/bash
set -euo pipefail

list_functions() {
  local src
  src="$1"
  perl -n -e "if (/^Function (?:Kernel_C\\.(?:StrictC')?)?(\\S+)\\s/) { print \"\$1\\n\" }" "${BV_TARGET_DIR}${src}Functions.txt" | sort
}

comm -12 <(list_functions ASM) <(list_functions C)

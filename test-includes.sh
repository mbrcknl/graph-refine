#! /bin/bash
set -ex

# This script attempts to run graph-refine on the functions listed in includes.txt.
# It assumes that you have includes.txt and that latest contains a number of pre-prepared
# files.

# Based on Ed Pierchalski's "dodgy-script".

export L4V_ARCH="${L4V_ARCH:?Must set L4V_ARCH}"

export TV_ROOT="${TV_ROOT:?Must set TV_ROOT.

TV_ROOT should point to a sync'd and init'd verification checkout, i.e. it
should point to the parent directory of l4v, graph-refine, HOL4, etc.}"

export TV_ROOT="$(realpath "${TV_ROOT}")"


#~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Build solverlist if needed, copy it to an appropriate location
#~~~~~~~~~~~~~~~~~~~~~~~~~~~

# This is currently dormant so that it does not disrupt any workflows. 
# We assumed that you have an appropriate .solverlist 
# To make this script agnostic to solverlists, uncomment these lines

#cd $TV_ROOT

#source graph-refine/make_solverlist.sh

#cp smtsolvers/solverlist graph-refine/.solverlist

#~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Copy pre-prepared inputs
#~~~~~~~~~~~~~~~~~~~~~~~~~~~

cd $TV_ROOT/graph-refine/seL4-example

cp latest/ASMFunctions.txt ASMFunctions.txt
cp latest/CFunctions.txt CFunctions.txt
cp latest/StackBounds.txt StackBounds.txt
cp latest/target.py target.py

#~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Read includes.txt
#~~~~~~~~~~~~~~~~~~~~~~~~~~~

cd $TV_ROOT/graph-refine

mapfile -t <includes.txt
TV_INCLUDES="${MAPFILE[@]}"

#~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Do the analysis
#~~~~~~~~~~~~~~~~~~~~~~~~~~~

cd $TV_ROOT/graph-refine

python graph-refine.py seL4-example trace-to:seL4-example/report.txt -include-only ${TV_INCLUDES} -end-include-only all

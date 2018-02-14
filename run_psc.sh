#!/usr/bin/env bash

# Shell settings
# fail on failed commands
# we can't fail on unset variables, because envirius uses them
set -e
# the exit status of a pipe is the last non-zero exit, or zero if all succeed
set -o pipefail

# Argument processing
if [ $# -ne 5 ]; then
    echo "usage: $0 GoEnv CP|DP|TS CN Port RestartSeconds"
    exit 1
fi

SCRIPT_DIR=`dirname "$0"`

USR_UPPER=`echo "$2" | tr 'a-z' 'A-Z'`
USR_LOWER=`echo "$2" | tr 'A-Z' 'a-z'`

# Prepare to launch the command
[ -f "$HOME/.envirius/nv" ] && . ~/.envirius/nv

cd "$SCRIPT_DIR"/"$USR_UPPER"

# Echo commands
set -x

while true; do
    # Launch the command in the correct environment
    # Don't exit this script on a non-zero exit status, just print it
    nv do "$1" "go run $USR_LOWER.go -c $3 -p $4" 2>&1 | tee -a "$SCRIPT_DIR"/"$USR_LOWER.$3".log || echo "Exit $?"
    # Wait for relaunch
    sleep "$5"
done

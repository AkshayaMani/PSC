#!/usr/bin/env bash

# Shell settings
# fail on failed commands
# we can't fail on unset variables, because envirius uses them
set -e
# the exit status of a pipe is the last non-zero exit, or zero if all succeed
set -o pipefail

# Argument processing
if [ $# -lt 5 ]; then
    echo "usage: $0 GoEnv CP|DP|TS CN Port RestartSeconds [OptArg...]"
    exit 1
fi

PSC_SCRIPT_DIR=`dirname "$0"`

PSC_GOENV="$1"
shift

PSC_USR_UPPER=`echo "$1" | tr 'a-z' 'A-Z'`
PSC_USR_LOWER=`echo "$1" | tr 'A-Z' 'a-z'`
PSC_USR_CMD=`echo "$PSC_USR_LOWER" | head -c 1`
shift

PSC_CNAME="$1"
shift

PSC_PORT="$1"
shift

PSC_RESTART="$1"
shift

# Prepare to launch the command
[ -f "$HOME/.envirius/nv" ] && . ~/.envirius/nv

cd "$PSC_SCRIPT_DIR"/"$PSC_USR_UPPER"

# Echo commands
set -x

while true; do
    # Launch the command in the correct environment
    # Don't exit this script on a non-zero exit status, just print it
    echo "Launching PSC. To view logs, run tail -f" \
	 "$PSC_SCRIPT_DIR"/"$PSC_USR_LOWER.$PSC_CNAME".log
    nv do "$PSC_GOENV" \
        "go run $PSC_USR_LOWER.go -$PSC_USR_CMD $PSC_CNAME -p $PSC_PORT $@" \
        2>&1 \
        >> "$PSC_SCRIPT_DIR"/"$PSC_USR_LOWER.$PSC_CNAME".log \
        || echo "Exit $?"
    # Wait for relaunch
    sleep "$PSC_RESTART"
done

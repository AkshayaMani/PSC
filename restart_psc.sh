#!/usr/bin/env bash

# Kills all PSC processes, but leaves run_psc.sh running
# When run_psc.sh reaches its next restart interval, it will automatically
# start the new version

killall go
killall ts
killall cp
killall dp

# Argument processing
if [ $# -lt 1 ]; then
    echo "usage: $0 GoEnv"
    exit 1
fi

PSC_GOENV="$1"

# Prepare to launch the command
[ -f "$HOME/.envirius/nv" ] && . ~/.envirius/nv

# Activate environment
nv on "$PSC_GOENV"

# Upgrade PSC
cd $GOPATH/src/PSC
git pull

# Deactivate environment
nv off

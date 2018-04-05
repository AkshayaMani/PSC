#!/usr/bin/env bash

# Kills all PSC processes, but leaves run_psc.sh running
# When run_psc.sh reaches its next restart interval, it will automatically
# start the new version

killall go
killall ts
killall cp
killall dp

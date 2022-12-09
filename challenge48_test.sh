#!/bin/sh
set -ex

for i in $(seq 1 20); do
    ARG=$(cat /dev/random | LC_ALL=C tr -dc '[:alnum:]' | head -c 80)
    ./set6_challenge48 $RANDOM "$ARG"
done

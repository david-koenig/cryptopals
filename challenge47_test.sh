#!/bin/sh
set -ex

for i in $(seq 1 20); do
    ./set6_challenge47 "$RANDOM"
done

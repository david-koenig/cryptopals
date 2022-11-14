#!/bin/sh
set -ex

for i in $(seq 1 20); do
    ARG=$(cat /dev/random | tr -dc '[:alnum:]' | head -c 80)
    ./set6_challenge48 $(shuf -i 0-9999999 -n1) "$ARG"
done

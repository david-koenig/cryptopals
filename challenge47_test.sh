#!/bin/sh
set -ex

for i in $(seq 1 20); do
    ./set6_challenge47 $(shuf -i 0-9999999 -n1)
done

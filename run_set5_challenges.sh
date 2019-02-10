#!/bin/sh
set -e

make set5

CMD33='./set5_challenge33'

for CMD in "$CMD33" ; do
    echo "Running command: $CMD"
    echo "---------OUTPUT---------"
    eval $CMD
    echo "-------END OUTPUT-------"
    echo ""
done

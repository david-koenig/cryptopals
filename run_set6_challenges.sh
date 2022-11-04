#!/bin/sh
set -e

CMD41='./set6_challenge41 918273645'

for CMD in "$CMD41" ; do
    echo "Running command: $CMD"
    echo "---------OUTPUT---------"
    eval $CMD
    echo "-------END OUTPUT-------"
    echo ""
done

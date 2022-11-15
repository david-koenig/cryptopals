#!/bin/sh
set -e

CMD49a='./set7_challenge49a 999888777'

for CMD in "$CMD49a" ; do
    echo "Running command: $CMD"
    echo "---------OUTPUT---------"
    eval $CMD
    echo "-------END OUTPUT-------"
    echo ""
done

#!/bin/sh
set -e

CMD41='./set6_challenge41 918273645'
CMD42='./set6_challenge42 12348765 "hi mom"'

for CMD in "$CMD41" "$CMD42" ; do
    echo "Running command: $CMD"
    echo "---------OUTPUT---------"
    eval $CMD
    echo "-------END OUTPUT-------"
    echo ""
done

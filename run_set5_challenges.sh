#!/bin/sh
set -e

CMD33='./set5_challenge33'
CMD34a='./set5_challenge34a 8675309'
CMD34b='./set5_challenge34b 1234567'

for CMD in "$CMD33" "$CMD34a" "$CMD34b" ; do
    echo "Running command: $CMD"
    echo "---------OUTPUT---------"
    eval $CMD
    echo "-------END OUTPUT-------"
    echo ""
done

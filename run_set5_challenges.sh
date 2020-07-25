#!/bin/sh
set -e

CMD33='./set5_challenge33'
CMD34='./set5_challenge34 8675309'

for CMD in "$CMD33" "$CMD34" ; do
    echo "Running command: $CMD"
    echo "---------OUTPUT---------"
    eval $CMD
    echo "-------END OUTPUT-------"
    echo ""
done

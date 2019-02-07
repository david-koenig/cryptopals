#!/bin/sh
set -e

make set4

CMD25='./set4_challenge25 25.txt 385438'
CMD26='./set4_challenge26 8675309'
CMD27='./set4_challenge27 98765432'

for CMD in "$CMD25" "$CMD26" "$CMD27" ; do
    echo "Running command: $CMD"
    echo "---------OUTPUT---------"
    eval $CMD
    echo "-------END OUTPUT-------"
    echo ""
done

#!/bin/sh
set -e

CMD25='./set4_challenge25 25.txt 385438'
CMD26='./set4_challenge26 8675309'
CMD27='./set4_challenge27 98765432'
CMD28='./set4_challenge28 12345678'
CMD29='./set4_challenge29 12121212'
CMD30='./set4_challenge30 89898989'

for CMD in "$CMD25" "$CMD26" "$CMD27" "$CMD28" "$CMD29" "$CMD30" ; do
    echo "Running command: $CMD"
    echo "---------OUTPUT---------"
    eval $CMD
    echo "-------END OUTPUT-------"
    echo ""
done

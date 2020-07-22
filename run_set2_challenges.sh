#!/bin/sh
set -e

CMD9='./set2_challenge9 "YELLOW SUBMARINE" 20'
CMD10='./set2_challenge10 10.txt'
CMD11A='./set2_challenge11 8675309'
CMD11B='./set2_challenge11 99999999'
CMD12='./set2_challenge12 90210'
CMD13='./set2_challenge13 99775533'
CMD14='./set2_challenge14 123456789'
CMD15='./set2_challenge15'
CMD16='./set2_challenge16 987654321'

for CMD in "$CMD9" "$CMD10" "$CMD11A" "$CMD11B" "$CMD12" "$CMD13" "$CMD14" "$CMD15" "$CMD16" ; do
    echo "Running command: $CMD"
    echo "---------OUTPUT---------"
    eval $CMD
    echo "-------END OUTPUT-------"
    echo ""
done

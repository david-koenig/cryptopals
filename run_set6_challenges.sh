#!/bin/sh
set -e

CMD41='./set6_challenge41 918273645'
CMD42='./set6_challenge42 12348765 "hi mom"'
CMD43a='./set6_challenge43a 95847362'
CMD43b='./set6_challenge43b'
CMD44='./set6_challenge44'
CMD45='./set6_challenge45 56473829'
CMD46='./set6_challenge46 90210'
CMD47='./set6_challenge47 34'

for CMD in "$CMD41" "$CMD42" "$CMD43a" "$CMD43b" "$CMD44" "$CMD45" "$CMD46" "$CMD47" ; do
    echo "Running command: $CMD"
    echo "---------OUTPUT---------"
    eval $CMD
    echo "-------END OUTPUT-------"
    echo ""
done

#!/bin/sh
set -e

CMD41='./set6_challenge41 918273645'
CMD42='./set6_challenge42 12348765 "hi mom"'
CMD43a='./set6_challenge43a 95847362'
CMD43b='./set6_challenge43b'
CMD44='./set6_challenge44'

for CMD in "$CMD41" "$CMD42" "$CMD43a" "$CMD43b" "$CMD44" ; do
    echo "Running command: $CMD"
    echo "---------OUTPUT---------"
    eval $CMD
    echo "-------END OUTPUT-------"
    echo ""
done

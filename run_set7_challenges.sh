#!/bin/sh
set -e

CMD49a='./set7_challenge49a 999888777'
CMD49b='./set7_challenge49b 111222333'
CMD50='./set7_challenge50'

for CMD in "$CMD49a" "$CMD49b" "$CMD50" ; do
    echo "Running command: $CMD"
    echo "---------OUTPUT---------"
    eval $CMD
    echo "-------END OUTPUT-------"
    echo ""
done

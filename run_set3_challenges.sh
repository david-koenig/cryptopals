#!/bin/sh
set -e

CMD17='./set3_challenge17 385438'
CMD18='./set3_challenge18'
CMD19='./set3_challenge19 1916'
CMD20='./set3_challenge20 20.txt 153153153'
CMD21='./set3_challenge21 4357'
CMD22='./set3_challenge22 666'
CMD23='./set3_challenge23 2323232323'
CMD24A='./set3_challenge24a 6666'
CMD24B='./set3_challenge24b 423679'

for CMD in "$CMD17" "$CMD18" "$CMD19" "$CMD20" "$CMD21" "$CMD22" "$CMD23" "$CMD24A" "$CMD24B" ; do
    echo "Running command: $CMD"
    echo "---------OUTPUT---------"
    eval $CMD
    echo "-------END OUTPUT-------"
    echo ""
done

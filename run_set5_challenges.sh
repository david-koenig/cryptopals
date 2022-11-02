#!/bin/sh
set -e

CMD33='./set5_challenge33'
CMD34a='./set5_challenge34a 8675309'
CMD34b='./set5_challenge34b 1234567'
CMD35='./set5_challenge35 278789'
CMD36='./set5_challenge36 349781 davek@noreply.com rolypolyfishheads'
CMD37='./set5_challenge37 987654 davek@got.hacked dummy'
CMD38a='./set5_challenge38a 765432 davek@noreply.com rolypolyfishheads'
CMD38b='./set5_challenge38b 345678 davek@noreply.com bacchanalian /usr/share/dict/words'
CMD39='./set5_challenge39 8967452310'

for CMD in "$CMD33" "$CMD34a" "$CMD34b" "$CMD35" "$CMD36" "$CMD37" "$CMD38a" "$CMD38b" "$CMD39" ; do
    echo "Running command: $CMD"
    echo "---------OUTPUT---------"
    eval $CMD
    echo "-------END OUTPUT-------"
    echo ""
done

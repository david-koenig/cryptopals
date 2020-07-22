#!/bin/sh
set -e

CMD1='./set1_challenge1 49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
CMD2='./set1_challenge2 1c0111001f010100061a024b53535009181c 686974207468652062756c6c277320657965'
CMD3='./set1_challenge3 1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
CMD4='./set1_challenge4 4.txt'
CMD5='./set1_challenge5 "Burning '\''em, if you ain'\''t quick and nimble
I go crazy when I hear a cymbal"'
CMD6A='./set1_challenge6a 6.txt'
CMD6B='./set1_challenge6b 6.txt 29'
CMD6C='./set1_challenge6c 6.txt 5465726d696e61746f7220583a204272696e6720746865206e6f697365'
CMD7='./set1_challenge7 7.txt'
CMD8='./set1_challenge8 8.txt'

for CMD in "$CMD1" "$CMD2" "$CMD3" "$CMD4" "$CMD5" "$CMD6A" "$CMD6B" "$CMD6C" "$CMD7" "$CMD8" ; do
    echo "Running command: $CMD"
    echo "---------OUTPUT---------"
    eval $CMD
    echo "-------END OUTPUT-------"
    echo ""
done

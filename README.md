# Cryptopals Challenge Solutions

This package contains a set of solutions to the Cryptopals challenges at https://cryptopals.com/.
It is a work in progress. The solutions are written in C and C++, and the package is built with a
simple makefile.

Set the environmental variable OPENSSL_ROOT_DIR before building. For example:

    export OPENSSL_ROOT_DIR=/usr/local/opt/openssl@1.1

The only dependencies of this package are gcc, g++, and the OpenSSL C libraries.

There are scripts called `run_set1_challenges.sh`, etc., which will automatically build the challenges
in that set and run the binaries with command lines that demonstrate the solutions.

Each binary can also be run with no arguments to produce a usage statement.

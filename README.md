# Cryptopals Challenge Solutions

This package contains a set of solutions to the Cryptopals challenges at https://cryptopals.com/.
It is a work in progress. The solutions are written in C and C++, and the package is built with CMake.

Dependencies are C and C++ compilers, CMake, the OpenSSL C libraries, and the GNU Multi-Precision
library. (GMP)

To install these dependencies on Ubuntu:

    sudo apt-get install g++ libssl-dev libgmp-dev cmake

To install them on Amazon Linux or other yum-based systems:

    sudo yum install gcc-c++ openssl-devel gmp-devel cmake

Standard build recipe, starting from the parent directory of cryptopals:

    mkdir cryptopals_build
    cd cryptopals_build
    cmake ../cryptopals
    cmake --build .

Here is an example build recipe using compilers and OpenSSL installed in nonstandard places (as Brew
does on Mac), starting from the parent directory of cryptopals.

    mkdir cryptopals_build
    cd cryptopals_build
    cmake -DCMAKE_C_COMPILER=/usr/local/bin/gcc-10 -DCMAKE_CXX_COMPILER=/usr/local/bin/g++-10 -DOPENSSL_ROOT_DIR=/usr/local/opt/openssl@1.1 ../cryptopals
    cmake --build .

There are scripts called `run_set1_challenges.sh`, etc., which will automatically run the binaries
with command lines that demonstrate the solutions.

Each binary can also be run with no arguments to produce a usage statement.

## About randomness and seeds

Many (most?) of these attacks are designed to work on unknown random cryptovariables. When you write
attacks like this it is both helpful to be able to test them against a variety of inputs *and* to hold
those inputs constant while you are trying to get the details of the attack correct. For that reason, I
have generally taken the approach of feeding a seed to the RNG at the command line. This allows me to
always keep that seed the same and generate the same set of random values until the attack works, and
then to run it many more times against other input values to check that the attack is still working in
the general case.

The purpose here is not to have good cryptographically random input through the RNG seeded at the
command line, but simply to be able to generate different test cases quickly. The shell scripts
to run the challenges use arbitrary inputs to the seeds. There is nothing special about those values.
They are just individual examples of the attack that is being run. In general you can change those seeds
to any other value to have an equivalent example of the attack. The only exception is that sometimes
I have chosen different random seeds to illustrate different code paths. (See set 2 challenge 11,
though the particular seeds I have chosen might not have the effect of portably reaching different paths.)

For easy portability and not having to take extra dependencies, I'm just using the C standard library
`random()` to help generate different test cases. The cryptographic strength or weakness of `random()` is
not the point of any of these exercises. Note that there are a few attacks which are about attacking
*other* RNGs in the code.
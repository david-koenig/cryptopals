#include "cryptopals_mersenne.h"
#include <cstdio>
#include <cstdlib>
#include <ctime>

int main(int argc, char ** argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s seed\nCrack an MT19937 seed\n", argv[0]);
        return 1;
    }
    // Using user provided seed and rand/srand for time when MT19937 is seeded.
    srand(atoi(argv[1]));

    /* Seed Mersenne Twister at some unknown time. In order not to wait forever,
     * we won't have program sleep, but instead just pick a time in the not too
     * distant past as its seed value.
     */
    time_t now = time(NULL);
    const int max_time_ago = 3600; // 3600 seconds, i.e. one hour ago
    cryptopals::mt19937 mt(now - rand() % max_time_ago);

    // capture first random output from it
    uint32_t first_rand = mt.rand();
    printf("first_rand = %u\nAttempting to crack seed...\n", first_rand);

    // exhaust over time interval to find seed
    time_t begin_time = now - max_time_ago;

    time_t seed;
    for (seed = begin_time ; seed < now ; ++seed) {
        mt.srand(seed);
        if (mt.rand() == first_rand) {
            printf("Cracked! Seed = %lu\n", seed);
            return 0;
        }
    }
    printf("Failed to crack seed!\n");
    return 1;
}

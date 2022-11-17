#include "cryptopals_profile.h"
#include <iostream>
#include <sstream>
#include <cstring>
#include <iomanip>

const size_t BLOCK_SIZE = 16;

// input email and output printable string of what unencrypted profile looks like
// just for demonstration purposes
std::string printable_profile(const std::string & email) {
    std::string profile("email=");
    profile += email + "&uid=10&role=user";
    size_t pad_len = BLOCK_SIZE - (profile.size() % BLOCK_SIZE);
    profile.append(pad_len, 'P'); // not actual block byte, which isn't printable
    return profile;
}

// pretty print of output of printable_profile function above
void print_profile(const std::string & profile, char label, size_t block=std::string::npos, bool final_newline=true) {
    const size_t print_width = 2 * BLOCK_SIZE + 1;
    const size_t space = 4; // spaces between label, e.g., (A0), and plaintext block

    // version of C++ compiler I am using does not properly support range based loops so this is a work-around
    size_t min;
    size_t max;
    if (block != std::string::npos) { // print just the specified block
        min = block;
        max = block + 1;
    } else { // print them all
        min = 0;
        max = profile.size() / BLOCK_SIZE;
    }
    for (size_t block_idx = min; block_idx < max ; ++block_idx) {
        std::ostringstream block_label_s;
        block_label_s << '(' << label << block_idx << ')';
        std::string block_label = block_label_s.str();
        std::cout << std::setw(block_label.size() + space) << std::left << block_label;
        std::cout << std::setw(print_width - block_label.size() - space) << std::left << profile.substr(BLOCK_SIZE * block_idx, BLOCK_SIZE);
    }
    if (final_newline) std::cout << std::endl;
}

int main(int argc, char ** argv) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " seed" << std::endl;
        std::cerr << "Hack a profile" << std::endl;
        return 1;
    }
    std::istringstream ss(argv[1]);
    int seed;
    if (!(ss >> seed)) {
        std::cerr << "Invalid number: " << argv[1] << std::endl;
        return 1;
    }
    init_random_encrypt(seed);

    std::cout << "PKCS padding bytes will be printed as \"P\" for legibility." << std::endl << std::endl;

    std::cout << "First pick an email address to get the role name all by itself in the last block" << std::endl;
    std::string emailA("admin@bar.com");
    byte_array cipherA = generate_encrypted_profile(emailA);

    print_profile(printable_profile(emailA), 'A');
    print_byte_array_blocks(cipherA, BLOCK_SIZE, ' ');

    std::cout << std::endl << "Then we want to replace that last block by admin with the appropriate padding." << std::endl;
    std::cout << "How can we get encryption of that? By sticking it in the email address!" << std::endl;

    /* actual input to encryption function will be "foo@bar.coadmin" plus 11 bytes of 0x0b to simulate PKCS7 padding
     * the exact characters of the beginning of string "foo@bar.co" do not matter but are selected to make sure input
     * passes email address validation and so that "admin" will start at the beginning of a cipher block.
     */
    std::string emailB("foo@bar.coadmin");
    std::string emailB_printable(emailB);
    char c = 0x0b;
    emailB.append(11, c);
    emailB_printable.append(11, 'P');
    byte_array cipherB = generate_encrypted_profile(emailB);

    print_profile(printable_profile(emailB_printable), 'B');
    print_byte_array_blocks(cipherB, BLOCK_SIZE, ' ');

    std::cout << std::endl << "Constructing frankenstein cipher..." << std::endl;
    
    byte_array cipherC = alloc_byte_array(3 * BLOCK_SIZE);
    memcpy(cipherC.bytes, cipherA.bytes, 2 * BLOCK_SIZE);
    memcpy(cipherC.bytes + 2*BLOCK_SIZE, cipherB.bytes + BLOCK_SIZE, BLOCK_SIZE);
    
    print_profile(printable_profile(emailA), 'A', 0, false);
    print_profile(printable_profile(emailA), 'A', 1, false);
    print_profile(printable_profile(emailB_printable), 'B', 1);
    print_byte_array_blocks(cipherC, BLOCK_SIZE, ' ');

    std::cout << std::endl << "Decrypting frankenstein cipher yields this profile..." << std::endl;
    auto profile = decrypt_profile(cipherC);
    print_map(profile);

    free_byte_arrays(cipherA, cipherB, cipherC, NO_BA);
    cleanup_random_encrypt();
    return 0;
}

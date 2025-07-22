// cryptor.cpp
// github: s4yr3x
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#define CHACHA20_IMPLEMENTATION
#include "libs/chacha/chacha20.h"

#include <iostream>
#include <fstream>
#include <vector>
#include <cstdint>

static const uint8_t aKey[32] = {
    // [EncryptionDLLModule] This functionality is part of the full version only.
};

static const uint8_t aNonce[12] = {
    // [EncryptionDLLModule] This functionality is part of the full version only.
};

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <input_file> <output_file>" << std::endl;
        return 1;
    }

    std::ifstream inFile(argv[1], std::ios::binary);
    if (!inFile) {
        std::cerr << "Error opening input file: " << argv[1] << std::endl;
        return 1;
    }

    std::vector<uint8_t> buffer((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());
    inFile.close();

    chacha20_xor(aKey, aNonce, buffer.data(), buffer.size(), 0);

    std::ofstream outFile(argv[2], std::ios::binary);
    if (!outFile) {
        std::cerr << "Error opening output file: " << argv[2] << std::endl;
        return 1;
    }

    outFile.write(reinterpret_cast<const char*>(buffer.data()), buffer.size());
    outFile.close();

    std::cout << "Successfully ChaCha20-crypted " << argv[1] << " to " << argv[2] << std::endl;
    return 0;
}
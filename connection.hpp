#pragma once

#include <sodium.h>
#include <cstddef>
#include "defines.hpp"

class Authority {
public:
    static int getDigitalSignature(int clientSocket, const char* identifier, unsigned char user_pk[], size_t user_pk_size);
    static int sendDigitalSignature(int serverSocket, unsigned char authority_pk[], unsigned char authority_sk[], size_t authority_pk_size);
};


struct SignRequest {
    unsigned char identifier[MAX_ID_LEN];
    unsigned char public_key[crypto_sign_PUBLICKEYBYTES];
};
struct SignedResponse {
    unsigned char signature[crypto_sign_BYTES];
    unsigned char signer_pk[crypto_sign_PUBLICKEYBYTES];
};

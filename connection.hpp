#pragma once

#include <optional>
#include <sodium.h>
#include <cstddef>
#include "defines.hpp"

struct Handshake {
    unsigned char identifier[MAX_ID_LEN];
    unsigned char nonce[crypto_box_NONCEBYTES];
    unsigned char signature[crypto_sign_BYTES];
    unsigned char public_key[crypto_kx_PUBLICKEYBYTES];
};

struct SignRequest {
    unsigned char identifier[MAX_ID_LEN];
    unsigned char public_key[crypto_kx_PUBLICKEYBYTES];
};
struct SignedResponse {
    unsigned char signature[crypto_sign_BYTES];
    unsigned char signer_pk[crypto_sign_PUBLICKEYBYTES];
};

class Authority {
public:
    static std::optional<SignedResponse> getDigitalSignature(const char* identifier, unsigned char user_pk[], size_t user_pk_size);
    static int sendDigitalSignature(int serverSocket, unsigned char authority_pk[], unsigned char authority_sk[], size_t authority_pk_size);
};

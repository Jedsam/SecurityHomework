#ifndef AUTHORITY_H_
#define AUTHORITY_H_
#include <sodium.h>

#define MAX_ID_LEN 256

struct SignedResponse {
    unsigned char signature[crypto_sign_BYTES];
    unsigned char signer_pk[crypto_sign_PUBLICKEYBYTES];
};
#endif  // AUTHORITY_H_

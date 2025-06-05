#pragma once

#include <sodium.h>

#include <cstring>
#include <optional>
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
struct HeaderMessage {
    char messageType;
    int bit_length;
};

class Connect {
public:
    int getDigitalSignature();
    int sendDigitalSignature(int serverSocket, unsigned char authority_pk[], unsigned char authority_sk[], size_t authority_pk_size);
    int recieveHandshake();
    int recieveMessage();
    int sendMessage();
    int sendHandshake();
    int generateServerSessionKeys();
    int generateClientSessionKeys();
    int generateCommunicationKeys();
    void generateNonce();
    void closeSocket();
    void setSocket(int socket);
    explicit Connect(const char *id);
private:
    char identifier[MAX_ID_LEN];
    int cur_socket;
    uint64_t message_counter;
    Handshake handshake_target, handshake_initiator;
    SignedResponse signed_response;
    unsigned char public_key[crypto_kx_PUBLICKEYBYTES], secret_key[crypto_kx_SECRETKEYBYTES];
    // Session keys
    unsigned char rx[crypto_kx_SESSIONKEYBYTES];  // key for receiving
    unsigned char tx[crypto_kx_SESSIONKEYBYTES];  // key for sending
    unsigned char iv[crypto_secretbox_NONCEBYTES];  // IV key
    unsigned char mac_key_in[crypto_auth_KEYBYTES];  // MAC key in
    unsigned char mac_key_out[crypto_auth_KEYBYTES];  // MAC key out
};

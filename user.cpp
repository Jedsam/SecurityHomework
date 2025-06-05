#include <sodium.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <string>
#include <cstring>
#include <iostream>
#include <format>
#include <vector>

#include "Logger.hpp"
#include "defines.hpp"
#include "connection.hpp"
#include "user.hpp"

int main() {
    if (sodium_init() == -1) {
        std::cerr << "Failed to initialize libsodium" << std::endl;
        return 1;
    }

    Logger::Init("user_log.txt");
    // client identifier
    const char identifier[MAX_ID_LEN]= "bobTheReal";

    // ECDH keys setup
    unsigned char user_pk[crypto_kx_PUBLICKEYBYTES], user_sk[crypto_kx_SECRETKEYBYTES];
    crypto_kx_keypair(user_pk, user_sk);  // Create PK and SK pairs

    std::cout << std::format("User is up!") << std::endl;

    // Print the public keys
    std::string formatted_pk;
    for (int i = 0; i < crypto_kx_PUBLICKEYBYTES; ++i) {
        formatted_pk += std::format("{:02x}", user_pk[i]);
    }
    std::cout << "Public Keys: " << formatted_pk << std::endl;


    // Get the digital signature of user
    std::optional<SignedResponse> optResponse = Authority::getDigitalSignature(identifier, user_pk, sizeof(user_pk));
    if (!optResponse.has_value()) {
        std::cerr << "Error trying to get a response from CA\n";
        return -1;
    }


    // Creating handshake
    Handshake handshake_user;
    // Generate nonce
    randombytes_buf(handshake_user.nonce, sizeof(handshake_user.nonce));

    std::string formatted_nonce;
    for (int i = 0; i < crypto_kx_PUBLICKEYBYTES; ++i) {
        formatted_nonce += std::format("{:02x}", handshake_user.nonce[i]);
    }
    std::cout << "Nonce: " << formatted_nonce << std::endl;
    std::memcpy(handshake_user.signature, optResponse->signature, sizeof(handshake_user.signature));
    std::memcpy(handshake_user.identifier, identifier, sizeof(identifier));
    std::memcpy(handshake_user.public_key, user_pk, sizeof(user_pk));

    // Connect to the server
    // creating socket
    int clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    // specifying address
    sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(SERVER_PORT);
    serverAddress.sin_addr.s_addr = INADDR_ANY;

    // sending connection request
    if (connect(clientSocket, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) == -1) {
        std::cout << std::format("Error connecting to server: {}", serverAddress.sin_addr.s_addr) << std::endl;
        return -1;
    }

    ssize_t r = send(clientSocket, &handshake_user, sizeof(handshake_user), 0);
    if (r != sizeof(handshake_user)) {
        std::cerr << "Failed to send handshake\n";
        close(clientSocket);
        return -1;
    }
    // Recieve handshake from server

    Handshake handshake_server;
    r = recv(clientSocket, &handshake_server, sizeof(handshake_server), MSG_WAITALL);
    if (r != sizeof(handshake_server)) {
        std::cerr << "Failed to receive signature response\n";
        close(clientSocket);
        return -1;
    }

    unsigned char msg[MAX_ID_LEN + crypto_kx_PUBLICKEYBYTES];
    std::memcpy(msg, handshake_server.identifier, MAX_ID_LEN);
    std::memcpy(msg + MAX_ID_LEN, handshake_server.public_key, crypto_kx_PUBLICKEYBYTES);

    if (crypto_sign_verify_detached(handshake_server.signature, msg, sizeof(msg), optResponse->signer_pk) == 0) {
        std::cout << "Server is verified: CA signed their identity + public key.\n";
    } else {
        std::cerr << "Invalid server: signature not trusted by the Authority.\n";
    }


    // Calculate symmetric keys
    unsigned char rx[crypto_kx_SESSIONKEYBYTES];  // key for receiving data
    unsigned char tx[crypto_kx_SESSIONKEYBYTES];  // key for sending data

    if (crypto_kx_client_session_keys(rx, tx, user_pk, user_sk, handshake_server.public_key) != 0) {
        std::cerr << "Failed to derive shared session keys\n";
        close(clientSocket);
        return -1;
    }

    unsigned char iv[crypto_secretbox_NONCEBYTES];  // 24 bytes
    uint64_t message_counter = 1;  // Increment for every new message

    // Combine both nonces + counter into a single buffer
    unsigned char nonce_input[2 * crypto_secretbox_NONCEBYTES + sizeof(message_counter)];
    std::memcpy(nonce_input, handshake_user.nonce, crypto_secretbox_NONCEBYTES);
    std::memcpy(nonce_input + crypto_secretbox_NONCEBYTES, handshake_server.nonce, crypto_secretbox_NONCEBYTES);
    std::memcpy(nonce_input + 2 * crypto_secretbox_NONCEBYTES, &message_counter, sizeof(message_counter));

    // Hash the nonce_input to generate a secure per-message nonce
    crypto_generichash(iv, sizeof(iv), nonce_input, sizeof(nonce_input), nullptr, 0);
    std::cout << "IV nonce: ";
    for (size_t i = 0; i < sizeof(iv); i++) {
        printf("%02x", iv[i]);
    }
    std::cout << std::endl;

    // Calculate MAC and IV
    unsigned char mac_key_in[crypto_auth_KEYBYTES];
    unsigned char mac_key_out[crypto_auth_KEYBYTES];

    crypto_generichash(mac_key_in, sizeof(mac_key_in), rx, sizeof(rx), nullptr, 0);
    crypto_generichash(mac_key_out, sizeof(mac_key_out), tx, sizeof(tx), nullptr, 0);

    // Message to send
    std::string plaintext = "Hello Server";

    // Compute HMAC-SHA256 (manual HMAC using crypto_auth for simplicity)
    unsigned char mac[crypto_auth_BYTES];
    crypto_auth(mac, reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.size(), mac_key_out);

    // Combine plaintext and MAC into one message
    std::vector<unsigned char> message_with_mac(plaintext.begin(), plaintext.end());
    message_with_mac.insert(message_with_mac.end(), mac, mac + crypto_auth_BYTES);

    // Reserve space for ciphertext: MAC (16 bytes) + message_with_mac
    std::vector<unsigned char> ciphertext(message_with_mac.size() + crypto_secretbox_MACBYTES);

    crypto_secretbox_easy(ciphertext.data(), message_with_mac.data(), message_with_mac.size(), iv, tx);

    ssize_t sent = send(clientSocket, ciphertext.data(), ciphertext.size(), 0);
    if (sent != (ssize_t)ciphertext.size()) {
        std::cerr << "Failed to send encrypted message.\n";
        close(clientSocket);
        return -1;
    }
    std::cout << "Sending ciphertext size: " << ciphertext.size() << std::endl;


    std::cout << "Encrypted message sent successfully.\n";

    return 0;
}

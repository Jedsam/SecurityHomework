#include <sodium.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <string>
#include <cstring>
#include <iostream>
#include <format>

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
    if (optResponse.has_value()) {
        SignedResponse signedResponse = optResponse.value();
    } else {
        std::cerr << "Error trying to get a response from CA\n";
        return -1;
    }

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

    // Creating the handshake_1
    Handshake_1 handshake;
    // Generate nonce
    randombytes_buf(handshake.nonce, sizeof(handshake.nonce));

    std::string formatted_nonce;
    for (int i = 0; i < crypto_kx_PUBLICKEYBYTES; ++i) {
        formatted_nonce += std::format("{:02x}", handshake.nonce[i]);
    }
    std::cout << "Nonce: " << formatted_nonce << std::endl;
    std::memcpy(handshake.signature, optResponse->signature, sizeof(handshake.signature));

    ssize_t r = send(clientSocket, &handshake, sizeof(handshake), 0);
    if (r != sizeof(handshake)) {
        std::cerr << "Failed to send handshake 1\n";
        close(clientSocket);
        return -1;
    }




    return 0;
}

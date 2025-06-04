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
    const char* identifier = "bobTheReal";
    uint16_t id_len = static_cast<uint16_t>(strlen(identifier));

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

    // creating socket
    int clientSocket = socket(AF_INET, SOCK_STREAM, 0);

    Authority::getDigitalSignature(clientSocket, identifier, id_len, user_pk, sizeof(user_pk));

    // closing socket
    close(clientSocket);
    return 0;
}

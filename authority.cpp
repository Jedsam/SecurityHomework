#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sodium.h>

#include <cstring>
#include <string>
#include <iostream>
#include <format>

#include "Logger.hpp"
#include "defines.hpp"
#include "connection.hpp"
#include "authority.hpp"

int main() {
    if (sodium_init() == -1) {
        std::cerr << "Failed to initialize libsodium" << std::endl;
        return 1;
    }

    Logger::Init("authority_log.txt");

    // EdDSA keys setup
    unsigned char authority_pk[crypto_sign_PUBLICKEYBYTES];
    unsigned char authority_sk[crypto_sign_SECRETKEYBYTES];
    crypto_sign_keypair(authority_pk, authority_sk);  // Create PK and SK pairs

    std::cout << "The Authority Server is starting" << std::endl;

    // Print the public keys
    std::string formatted_pk;
    for (int i = 0; i < crypto_kx_PUBLICKEYBYTES; ++i) {
        formatted_pk += std::format("{:02x}", authority_pk[i]);
    }
    std::cout << "Public Keys: " << formatted_pk << std::endl;

    // creating socket
    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);  // IPv4, TCP

    // Server address
    sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;  // IPv4
    serverAddress.sin_port = htons(AUTHORITY_PORT);
    serverAddress.sin_addr.s_addr = INADDR_ANY;  // Make the socket not listen to any particular IP and instead
    // make it listen to all the available IPs.

    // Bind to the address with the socket
    if (bind(serverSocket, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) == -1) {
        std::cout << std::format("Error binding to server: {}", serverAddress.sin_addr.s_addr) << std::endl;
        return -1;
    }

    // Listen to the socket, 5 max trials
    listen(serverSocket, 5);


    // Accepting connection request
    while (true) {
        Authority::sendDigitalSignature(serverSocket, authority_pk, authority_sk, sizeof(authority_pk));
    }

    // closing the socket.
    close(serverSocket);
    return 0;
}

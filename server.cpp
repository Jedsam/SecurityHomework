#include <netinet/in.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sodium.h>

#include <cstring>
#include <string>
#include <format>
#include <iostream>

#include "defines.hpp"
#include "Logger.hpp"
#include "connection.hpp"
#include "server.hpp"

int main() {
    if (sodium_init() == -1) {
        std::cerr << "Failed to initialize libsodium" << std::endl;
        return 1;
    }

    Logger::Init("server_log.txt");
    // Server identifier
    const char identifier[MAX_ID_LEN]= "AliceHeartwarmingServer";
    // ECDH keys setup
    unsigned char server_pk[crypto_kx_PUBLICKEYBYTES], server_sk[crypto_kx_SECRETKEYBYTES];
    crypto_kx_keypair(server_pk, server_sk);  // Create PK and SK pairs

    // Get the digital signature of user
    std::optional<SignedResponse> optResponse = Authority::getDigitalSignature(identifier, server_pk, sizeof(server_pk));
    if (!optResponse.has_value()) {
        std::cerr << "Error trying to get a response from CA\n";
        return -1;
    }

    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);  // IPv4, TCP
    // Server address
    sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;  // IPv4
    serverAddress.sin_port = htons(SERVER_PORT);
    serverAddress.sin_addr.s_addr = INADDR_ANY;  // Make the socket not listen to any particular IP and instead
    // make it listen to all the available IPs.

    // Bind to the address with the socket
    if (bind(serverSocket, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) == -1) {
        std::cout << std::format("Error binding to server: {}", serverAddress.sin_addr.s_addr) << std::endl;
        return -1;
    }
    std::cout << std::format("The server is starting!") << std::endl;

    // Listen to the socket, 5 max trials
    listen(serverSocket, 5);

    // Accepting connection request
    while (true) {
        int clientSocket = accept(serverSocket, nullptr, nullptr);
        Handshake handshake_user;
        ssize_t r = recv(clientSocket, &handshake_user, sizeof(handshake_user), MSG_WAITALL);
        if (r != sizeof(handshake_user)) {
            std::cerr << "Failed to receive signature response\n";
            close(clientSocket);
            continue;
        }

        unsigned char msg[MAX_ID_LEN + crypto_kx_PUBLICKEYBYTES];
        std::memcpy(msg, handshake_user.identifier, MAX_ID_LEN);
        std::memcpy(msg + MAX_ID_LEN, handshake_user.public_key, crypto_kx_PUBLICKEYBYTES);

        if (crypto_sign_verify_detached(handshake_user.signature, msg, sizeof(msg), optResponse->signer_pk) == 0) {
            std::cout << "User is verified: CA signed their identity + public key.\n";
        } else {
            std::cerr << "Invalid user: signature not trusted by the Authority.\n";
        }

        // Creating handshake
        Handshake handshake_server;
        // Generate nonce
        randombytes_buf(handshake_server.nonce, sizeof(handshake_server.nonce));
        std::string formatted_nonce;
        for (int i = 0; i < crypto_kx_PUBLICKEYBYTES; ++i) {
            formatted_nonce += std::format("{:02x}", handshake_server.nonce[i]);
        }

        std::cout << "Nonce: " << formatted_nonce << std::endl;
        std::memcpy(handshake_server.signature, optResponse->signature, sizeof(handshake_server.signature));
        std::memcpy(handshake_server.identifier, identifier, sizeof(identifier));
        std::memcpy(handshake_server.public_key, server_pk, sizeof(server_pk));

        // Send the handshake
        r = send(clientSocket, &handshake_server, sizeof(handshake_server), 0);
        if (r != sizeof(handshake_server)) {
            std::cerr << "Failed to send handshake\n";
            close(clientSocket);
            return -1;
        }

        close(clientSocket);
    }

    return 0;
}

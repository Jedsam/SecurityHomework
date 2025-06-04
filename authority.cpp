#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sodium.h>

#include <cstring>
#include <string>
#include <iostream>
#include <format>

#include "defines.hpp"
#include "authority.h"
#include "Logger.hpp"

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
        int clientSocket = accept(serverSocket, nullptr, nullptr);

        // Receive identifier length first
        uint16_t id_len_net;
        ssize_t r = recv(clientSocket, &id_len_net, sizeof(id_len_net), MSG_WAITALL);
        Logger::Log(std::format("Expected {} recieved actual {} sized message\n", sizeof(id_len_net), r));
        if (r != sizeof(id_len_net)) {
            std::cerr << "Failed to receive identifier length\n";
            close(clientSocket);
            continue;
        }

        uint16_t id_len = ntohs(id_len_net);
        if (id_len == 0 || id_len > MAX_ID_LEN) {
            std::cerr << "Invalid identifier length\n";
            close(clientSocket);
            continue;
        }

        // Receive identifier string
        char identifier[MAX_ID_LEN + 1] = {0};
        r = recv(clientSocket, identifier, id_len, MSG_WAITALL);
        Logger::Log(std::format("Expected {} recieved actual {} sized message\n",id_len, r));
        if (r != id_len) {
            std::cerr << "Failed to receive identifier\n";
            close(clientSocket);
            continue;
        }
        identifier[id_len] = '\0';
        std::cout << "Received ID: " << identifier << std::endl;

        // Receive client's public key (X25519)
        unsigned char client_pk[crypto_kx_PUBLICKEYBYTES];
        r = recv(clientSocket, client_pk, sizeof(client_pk), MSG_WAITALL);
        Logger::Log(std::format("Expected {} recieved actual {} sized message\n", sizeof(client_pk), r));
        if (r != sizeof(client_pk)) {
            std::cerr << "Failed to receive client public key\n";
            close(clientSocket);
            continue;
        }


        // Prepare message to sign = identifier + public key
        size_t msg_len = id_len + sizeof(client_pk);
        unsigned char* msg = new unsigned char[msg_len];
        memcpy(msg, identifier, id_len);
        memcpy(msg + id_len, client_pk, sizeof(client_pk));

        // Sign message
        SignedResponse response;
        crypto_sign_detached(response.signature, nullptr, msg, msg_len, authority_sk);
        memcpy(response.signer_pk, authority_pk, sizeof(authority_pk));


        // Send back the signature + signer's public key
        ssize_t sent = send(clientSocket, &response, sizeof(response), 0);
        Logger::Log(std::format("Expected {} but sent {} sized message\n", sizeof(response), sent));
        if (sent != sizeof(response)) {
            std::cerr << "Failed to send signature response\n";
        } else {
            std::cout << "Sent signature to client\n";
        }

        delete[] msg;

        close(clientSocket);
    }

// closing the socket.
    close(serverSocket);
    return 0;
}


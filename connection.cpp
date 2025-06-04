#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sodium.h>

#include <cstring>
#include <iostream>
#include <format>

#include "defines.hpp"
#include "Logger.hpp"
#include "connection.hpp"

int Authority::sendDigitalSignature(int serverSocket, unsigned char authority_pk[], unsigned char authority_sk[], size_t authority_pk_size) {
    int clientSocket = accept(serverSocket, nullptr, nullptr);

    // Receive identifier string
    char identifier[MAX_ID_LEN] = {0};
    ssize_t r = recv(clientSocket, identifier, MAX_ID_LEN, MSG_WAITALL);
    Logger::Log(std::format("Expected {} recieved actual {} sized message\n", MAX_ID_LEN, r));
    if (r != MAX_ID_LEN) {
        std::cerr << "Failed to receive identifier\n";
        close(clientSocket);
        return -1;
    }
    identifier[MAX_ID_LEN] = '\0';
    std::cout << "Received ID: " << identifier << std::endl;

    // Receive client's public key (X25519)
    unsigned char client_pk[crypto_kx_PUBLICKEYBYTES];
    r = recv(clientSocket, client_pk, sizeof(client_pk), MSG_WAITALL);
    Logger::Log(std::format("Expected {} recieved actual {} sized message\n", sizeof(client_pk), r));
    if (r != sizeof(client_pk)) {
        std::cerr << "Failed to receive client public key\n";
        close(clientSocket);
        return -1;
    }


    // Prepare message to sign = identifier + public key
    size_t msg_len = MAX_ID_LEN + sizeof(client_pk);
    unsigned char* msg = new unsigned char[msg_len];
    memcpy(msg, identifier, MAX_ID_LEN);
    memcpy(msg + MAX_ID_LEN, client_pk, sizeof(client_pk));

    // Sign message
    SignedResponse response;
    crypto_sign_detached(response.signature, nullptr, msg, msg_len, authority_sk);
    memcpy(response.signer_pk, authority_pk, authority_pk_size);


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
    return 0;
}
int Authority::getDigitalSignature(int clientSocket, const char* identifier, unsigned char user_pk[], size_t user_pk_size) {
    // specifying address
    sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(AUTHORITY_PORT);
    serverAddress.sin_addr.s_addr = INADDR_ANY;

    // sending connection request
    if (connect(clientSocket, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) == -1) {
        std::cout << std::format("Error connecting to CA: {}", serverAddress.sin_addr.s_addr) << std::endl;
        return 0;
    }


    // Send identifier string
    ssize_t r = send(clientSocket, identifier, MAX_ID_LEN, 0);
    Logger::Log(std::format("Expected {} sent actual {} sized message\n", MAX_ID_LEN, r));

    // send client public key
    r = send(clientSocket, user_pk, user_pk_size, 0);
    Logger::Log(std::format("Expected {} sent actual {} sized message\n", user_pk_size, r));
    std::cout << std::format("The user sent the public key!\n");


    SignedResponse response;
    r = recv(clientSocket, &response, sizeof(response), MSG_WAITALL);
    Logger::Log(std::format("Expected {} recieved actual {} sized message\n", sizeof(response), r));
    if (r != sizeof(response)) {
        std::cerr << "Failed to receive signature response\n";
        close(clientSocket);
        return 1;
    }

    // Verify signature over (identifier + public key)
    size_t msg_len = MAX_ID_LEN + user_pk_size;
    unsigned char* msg = new unsigned char[msg_len];
    memcpy(msg, identifier, MAX_ID_LEN);
    memcpy(msg + MAX_ID_LEN, user_pk, user_pk_size);

    if (crypto_sign_verify_detached(response.signature, msg, msg_len, response.signer_pk) == 0) {
        std::cout << "✔ Signature is valid — Authority trusts this identity and key!\n";
    } else {
        std::cerr << "✘ Signature verification failed!\n";
    }

    delete[] msg;

// closing socket
    close(clientSocket);
    return 1;
}

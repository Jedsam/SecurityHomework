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


    SignRequest signRequest;
    ssize_t r = recv(clientSocket, &signRequest, sizeof(signRequest), MSG_WAITALL);

    Logger::Log(std::format("Expected {} received actual {} sized message\n", sizeof(signRequest), r));

    if (r != sizeof(signRequest)) {
        std::cerr << "Failed to receive complete SignRequest\n";
        close(clientSocket);
        return -1;
    }

    // Null-terminate identifier safely
    signRequest.identifier[MAX_ID_LEN - 1] = '\0';

    std::cout << "Received ID: " << signRequest.identifier << std::endl;



    // Prepare message to sign = identifier + public key
    size_t msg_len = MAX_ID_LEN + sizeof(signRequest.public_key);
    unsigned char* msg = new unsigned char[msg_len];
    memcpy(msg, signRequest.identifier, MAX_ID_LEN);
    memcpy(msg + MAX_ID_LEN, signRequest.public_key, sizeof(signRequest.public_key));

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


    SignRequest signRequest;
    // Copy identifier and public key into the struct
    memcpy(signRequest.identifier, identifier, MAX_ID_LEN);
    memcpy(signRequest.public_key, user_pk, user_pk_size);  // Assume user_pk_size ≤ MAX_PK_SIZE

    // Send the struct
    ssize_t r = send(clientSocket, &signRequest, sizeof(signRequest), 0);
    Logger::Log(std::format("Expected {} sent actual {} sized message\n", sizeof(signRequest), r));
    std::cout << std::format("The user sent the identifier and public key!\n");


    // Take the response of the user
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

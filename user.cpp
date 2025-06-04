#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sodium.h>

#include <format>
#include "defines.hpp"
#include "user.hpp"
#include "authority.hpp"
#include "Logger.hpp"

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

    getDigitalSignature(clientSocket, identifier, id_len, user_pk, sizeof(user_pk));

    // closing socket
    close(clientSocket);
    return 0;
}
int getDigitalSignature(int clientSocket, const char* identifier, uint16_t id_len, unsigned char user_pk[], size_t user_pk_size) {
    // specifying address
    sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(AUTHORITY_PORT );
    serverAddress.sin_addr.s_addr = INADDR_ANY;

    // sending connection request
    if (connect(clientSocket, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) == -1) {
        std::cout << std::format("Error connecting to CA: {}", serverAddress.sin_addr.s_addr) << std::endl;
        return 0;
    }

    // Send identifier length
    uint16_t id_len_net = htons(id_len);
    ssize_t r = send(clientSocket, &id_len_net, sizeof(id_len_net), 0);
    Logger::Log(std::format("Expected {} sent actual {} sized message\n", sizeof(id_len_net), r));

    // Send identifier string
    r = send(clientSocket, identifier, id_len, 0);
    Logger::Log(std::format("Expected {} sent actual {} sized message\n", id_len, r));

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
    size_t msg_len = id_len + user_pk_size;
    unsigned char* msg = new unsigned char[msg_len];
    memcpy(msg, identifier, id_len);
    memcpy(msg + id_len, user_pk, user_pk_size);

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

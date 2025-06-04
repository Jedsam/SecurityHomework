#include <netinet/in.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sodium.h>

#include <format>
#include <iostream>

#include "defines.hpp"
#include "Logger.hpp"
#include "server.hpp"

int main() {
    if (sodium_init() == -1) {
        std::cerr << "Failed to initialize libsodium" << std::endl;
        return 1;
    }

    Logger::Init("server_log.txt");
    // ECDH keys setup
    unsigned char user_pk[crypto_kx_PUBLICKEYBYTES], user_sk[crypto_kx_SECRETKEYBYTES];
    crypto_kx_keypair(user_pk, user_sk);  // Create PK and SK pairs

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
        // recieving data
        char buffer[1024] = {0};
        recv(clientSocket, buffer, sizeof(buffer), 0);
        std::cout << "Message from client: " << buffer << std::endl;
        break;
    }

    return 0;
}

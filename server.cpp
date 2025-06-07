#include <netinet/in.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sodium.h>

#include <cstring>
#include <string>
#include <format>
#include <iostream>
#include <vector>

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
    // Initialize ECDH and identfier
    Connect myConnect("AliceHeartwarmingServer");

    // Get the digital signature of user
    if (myConnect.getDigitalSignature()) {
        std::cerr << "Error trying to get a response from CA\n";
        return -1;
    }

    // Starting up SERVER
    //
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

    int stopConnection, counter;
    // Accepting connection request
    while (true) {
        myConnect.setSocket(accept(serverSocket, nullptr, nullptr));
        // Receive the handshake from user
        if (myConnect.receiveHandshake()) {
            std::cerr << "Failed to receive handshake\n";
            return -1;
        }
        myConnect.generateNonce();
        if (myConnect.sendHandshake()) {
            std::cerr << "Failed to send handshake\n";
            return -1;
        }
        if (myConnect.generateServerSessionKeys()) {
            std::cerr << "Failed to generate server session keys\n";
            return -1;
        }
        if (myConnect.generateCommunicationKeys()) {
            std::cerr << "Failed to generate communication keys (MAC, IV)\n";
            return -1;
        }

        counter = 0;
        stopConnection = myConnect.receiveMessage();
        while (!stopConnection) {
            stopConnection = myConnect.receiveMessage();
            if (stopConnection == -1) {
                std::cerr << "Failed to receive message\n";
                counter++;
                if (counter > 5)
                    stopConnection = true;
                else
                    stopConnection = 0;
            }
        }
        myConnect.closeSocket();
    }

    return 0;
}

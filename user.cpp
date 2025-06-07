#include <sodium.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <string>
#include <cstring>
#include <iostream>
#include <format>
#include <vector>

#include "Logger.hpp"
#include "defines.hpp"
#include "connection.hpp"
#include "user.hpp"

int main() {
    if (sodium_init() == -1) {
        std::cerr << "Failed to initialize libsodium" << std::endl;
        return 1;
    }

    // Initialize logger
    Logger::Init("user_log.txt");
    // Initialize ECDH and identfier
    Connect myConnect("bobTheReal");
    std::cout << std::format("User is up!") << std::endl;

    // Get the digital signature of user
    if (myConnect.getDigitalSignature()) {
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

    myConnect.setSocket(clientSocket);
    // Generate nonce and send handshake to the server
    myConnect.generateNonce();
    if (myConnect.sendHandshake()) {
        std::cerr << "Failed to send handshake\n";
        return -1;
    }
    myConnect.receiveHandshake();

    if (myConnect.generateClientSessionKeys()) {
        std::cerr << "Failed to generate server session keys\n";
        return -1;
    }
    if (myConnect.generateCommunicationKeys()) {
        std::cerr << "Failed to generate communication keys (MAC, IV)\n";
        return -1;
    }


    int decision = 0;
    std::string plaintext;
    while (decision != 3) {
        std::cout << "Choose an option:\n"
                  << "1-) Send a text message\n"
                  << "2-) Send a file\n"
                  << "3-) Close connection\n";
        std::cin >> decision;

        // Clear the newline left by std::cin >> decision
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

        if (decision == 1) {
            std::cout << "Enter a text message : \n";
            std::getline(std::cin, plaintext);
            if (myConnect.sendTextMessage(plaintext, plaintext.size())) {
                std::cerr << "Failed to receive message\n";
                return -1;
            }
        } else if (decision == 2) {
            std::cout << "Enter the image path: \n";
            std::getline(std::cin, plaintext);
            if (myConnect.sendImageMessage(plaintext)) {
                std::cerr << "Failed to receive message\n";
                return -1;
            }

        } else if (decision == 3) {
            myConnect.closeSocket();
        }
    }
    return 0;
}

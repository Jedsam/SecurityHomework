#include <cstring>
#include <iostream>
#include <format>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include "defines.hpp"

int main() {
    std::cout << std::format("User is up!") << std::endl;
    // creating socket
    int clientSocket = socket(AF_INET, SOCK_STREAM, 0);

    // specifying address
    sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(SERVER_PORT);
    serverAddress.sin_addr.s_addr = INADDR_ANY;

    // sending connection request
    connect(clientSocket, (struct sockaddr *)&serverAddress,
            sizeof(serverAddress));

    // sending data
    const char *message = "Hello, server!";
    send(clientSocket, message, strlen(message), 0);
    std::cout << std::format("The user sent a message!\n");

    // closing socket
    close(clientSocket);
    return 0;
}

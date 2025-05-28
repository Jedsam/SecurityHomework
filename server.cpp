#include <iostream>
#include <format>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#define SERVER_PORT 334

using namespace std;

int main() {
    std::cout << std::format("The server is starting!");
    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);  // IPv4, TCP

    // Server address
    sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;  // IPv4
    serverAddress.sin_port = htons(SERVER_PORT);
    serverAddress.sin_addr.s_addr = INADDR_ANY;  // Make the socket not listen to any particular IP and instead make it listen to all the available IPs.

    // Bind to the address with the socket
    bind(serverSocket, (struct sockaddr*)&serverAddress, sizeof(serverAddress));

    // Listen to the socket, 5 max trials
    listen(serverSocket, 5);

    // Accepting connection request
    while(true) {
        int clientSocket = accept(serverSocket, nullptr, nullptr);
        // recieving data
        char buffer[1024] = { 0 };
        recv(clientSocket, buffer, sizeof(buffer), 0);
        cout << "Message from client: " << buffer
             << endl;
        break;
    }

    // closing the socket.
    close(serverSocket);
    return 0;
}


#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sodium.h>

#include <cstddef>
#include <cstring>
#include <string>
#include <iostream>
#include <format>
#include <vector>

#include "defines.hpp"
#include "Logger.hpp"
#include "connection.hpp"

Connect::Connect(const char *id) {
    std::strncpy(identifier, id, MAX_ID_LEN - 1);
    identifier[MAX_ID_LEN - 1] = '\0';
    crypto_kx_keypair(public_key, secret_key);  // Create PK and SK pairs

    // Print the public keys
    std::string formatted_pk;
    for (int i = 0; i < crypto_kx_PUBLICKEYBYTES; ++i) {
        formatted_pk += std::format("{:02x}", public_key[i]);
    }
    std::cout << "Public Keys: " << formatted_pk << std::endl;
}
int Connect::generateServerSessionKeys() {
    if (crypto_kx_server_session_keys(rx, tx, public_key, secret_key, handshake_target.public_key) != 0) {
        close(cur_socket);
        return -1;
    }
    return 0;
}
int Connect::sendTextMessage(const std::string& message, int size) {
    HeaderMessage myMessageHeader;
    myMessageHeader.messageType = TEXT;
    myMessageHeader.bit_length = size;

    // Serialize header (ensure no padding!)
    int message_size = sizeof(HeaderMessage);
    unsigned char message_text[sizeof(HeaderMessage)];
    memcpy(message_text, &myMessageHeader, message_size);

    if (sendEncryptedMessage(message_text, message_size, HEADER)) {
        std::cerr << "Failed to send encrypted header message.\n";
        return -1;
    }
    if (receiveACK(message_text, message_size, HEADER)) {
        std::cout << "Failed to receive ACK\n";
        return -1;
    }

    const unsigned char* data = reinterpret_cast<const unsigned char*>(message.data());
    if (sendEncryptedMessage(data, size, TEXT)) {
        std::cerr << "Failed to send encrypted text message.\n";
        return -1;
    }
    if (receiveACK(data, size, TEXT)) {
        std::cout << "Failed to receive ACK\n";
        return -1;
    }

    return 0;
}
int Connect::sendImageMessage(std::string file_location) {
    // Open image file in binary mode
    std::ifstream file(file_location, std::ios::binary);
    if (!file) {
        std::cerr << "Failed to open image file: " << file_location << std::endl;
        return -1;
    }

    // Read file content into a vector
    std::vector<unsigned char> image_data((std::istreambuf_iterator<char>(file)),
                                          std::istreambuf_iterator<char>());
    file.close();

    // Prepare header
    HeaderMessage myMessageHeader;
    myMessageHeader.messageType = IMAGE;
    myMessageHeader.bit_length = image_data.size();  // file size in bytes

    // Serialize header
    int message_size = sizeof(HeaderMessage);
    unsigned char message_text[sizeof(HeaderMessage)];
    std::memcpy(message_text, &myMessageHeader, message_size);

    // Send encrypted header
    if (sendEncryptedMessage(message_text, message_size, HEADER)) {
        std::cerr << "Failed to send encrypted header message.\n";
        return -1;
    }
    if (receiveACK(message_text, message_size, HEADER)) {
        std::cerr << "Failed to receive ACK\n";
        return -1;
    }

    // Send image data
    if (sendEncryptedMessage(image_data.data(), image_data.size(), IMAGE)) {
        std::cerr << "Failed to send encrypted image data.\n";
        return -1;
    }
    if (receiveACK(image_data.data(), image_data.size(), IMAGE)) {
        std::cerr << "Failed to receive ACK\n";
        return -1;
    }

    return 0;
}
int Connect::sendEncryptedMessage(const unsigned char* header_bytes, int header_size, char header_type) {
    // Compute HMAC-SHA256 (manual HMAC using crypto_auth for simplicity)
    unsigned char header_mac[crypto_auth_BYTES];
    crypto_auth(header_mac, header_bytes, header_size, mac_key_out);

    // Combine header + MAC into one buffer
    std::vector<unsigned char> message_with_mac;
    message_with_mac.insert(message_with_mac.end(), header_bytes, header_bytes + header_size);
    message_with_mac.insert(message_with_mac.end(), header_mac, header_mac + crypto_auth_BYTES);

    // Reserve space for ciphertext: MAC (16 bytes) + message_with_mac
    std::vector<unsigned char> ciphertext(message_with_mac.size() + crypto_secretbox_MACBYTES);

    crypto_secretbox_easy(ciphertext.data(), message_with_mac.data(), message_with_mac.size(), iv, tx);

    ssize_t sent = send(cur_socket, ciphertext.data(), ciphertext.size(), 0);
    if (sent != (ssize_t)ciphertext.size()) {
        std::cerr << "Failed to send encrypted message.\n";
        close(cur_socket);
        return -1;
    }
    logConnectionInfo(std::format("send ciphertext with size {} and type {} : {}", header_size, header_type, to_hex(ciphertext.data(), ciphertext.size())));
    std::cout << "Sending ciphertext size: " << ciphertext.size() << std::endl;
    std::cout << "Encrypted message sent successfully.\n";
    return 0;
}
int Connect::sendACK(const unsigned char* header_bytes, int header_size, char header_type) {
    Acknowledgment myAcknowledgment;
    myAcknowledgment.messageType = header_type;
    myAcknowledgment.bit_length = header_size;
    myAcknowledgment.checksum = calculateCheckSum(header_bytes, header_size);

    // Convert the variable to sendable data
    int message_size = sizeof(Acknowledgment);
    unsigned char message_text[sizeof(Acknowledgment)];
    memcpy(message_text, &myAcknowledgment, message_size);

    if (sendEncryptedMessage(message_text, message_size, ACK)) {
        std::cerr << "Failed to send encrypted header message.\n";
        return -1;
    }
    message_counter++;
    generateNonce();
    return 0;
}
int Connect::calculateCheckSum(const unsigned char* header_bytes, int header_size) {
    const size_t HASH_LEN = 4;
    unsigned char hash[HASH_LEN];

    crypto_generichash(hash, HASH_LEN, header_bytes, header_size, nullptr, 0);

    // Convert 4-byte hash to a uint32_t
    uint32_t checksum;
    std::memcpy(&checksum, hash, sizeof(checksum));

    std::cout << "Checksum (uint32_t): " << checksum << std::endl;
    return checksum;
}
int Connect::receiveACK(const unsigned char* header_bytes, int header_size, char header_type) {
    std::vector<unsigned char> ciphertext(sizeof(Acknowledgment) + crypto_auth_BYTES + crypto_secretbox_MACBYTES);

    ssize_t r = recv(cur_socket, ciphertext.data(), ciphertext.size(), MSG_WAITALL);
    if (r != (ssize_t)ciphertext.size()) {
        std::cerr << "Failed to receive full ACK ciphertext\n";
        close(cur_socket);
        return -1;
    }
    logConnectionInfo(std::format("send ciphertext with size {} and type {} : {}", header_size, header_type, to_hex(ciphertext.data(), ciphertext.size())));

    std::vector<unsigned char> plaintext = decryptReceivedMessage(ciphertext);

    Acknowledgment myMessageHeader;
    memcpy(&myMessageHeader, plaintext.data(), sizeof(Acknowledgment));
    int checksum;
    // ACK checks
    if (myMessageHeader.messageType != header_type) {
        std::cerr << std::format("Incorrect message type(expected {} but got {}), failed to verify the ACK\n", myMessageHeader.messageType, header_type);
        close(cur_socket);
        return -1;
    } else if (myMessageHeader.bit_length != header_size) {
        std::cerr << std::format("Incorrect message size(expected {} but got {}), failed to verify the ACK\n", myMessageHeader.bit_length, header_size);
        close(cur_socket);
        return -1;
    } else if (myMessageHeader.checksum != (checksum = calculateCheckSum(header_bytes, header_size))) {
        std::cerr << std::format("Incorrect checksum(expected {} but got {}), failed to verify the ACK\n", myMessageHeader.checksum, checksum);
        close(cur_socket);
        return -1;
    }
    message_counter++;
    generateNonce();
    return 0;
}

int Connect::receiveMessage() {
    // Receive ciphertext
    std::vector<unsigned char> ciphertext(sizeof(HeaderMessage) + crypto_auth_BYTES + crypto_secretbox_MACBYTES);

    ssize_t r = recv(cur_socket, ciphertext.data(), ciphertext.size(), MSG_WAITALL);
    if (r != (ssize_t)ciphertext.size()) {
        std::cerr << "Failed to receive full ciphertext\n";
        close(cur_socket);
        return -1;
    }
    logConnectionInfo(std::format("received ciphertext with size {} and type {} : {}", ciphertext.size(), HEADER, to_hex(ciphertext.data(), ciphertext.size())));

    std::vector<unsigned char> plaintext = decryptReceivedMessage(ciphertext);
    HeaderMessage myMessageHeader;
    memcpy(&myMessageHeader, plaintext.data(), sizeof(HeaderMessage));
    if (sendACK(plaintext.data(), plaintext.size(), HEADER)) {
        std::cout << "Failed to send ACK";
        return -1;
    }
    if (myMessageHeader.messageType == TEXT) {
        ciphertext.resize(myMessageHeader.bit_length + crypto_auth_BYTES + crypto_secretbox_MACBYTES);
        r = recv(cur_socket, ciphertext.data(), ciphertext.size(), MSG_WAITALL);
        if (r != (ssize_t)ciphertext.size()) {
            std::cerr << "Failed to receive full ciphertext\n";
        }
        logConnectionInfo(std::format("received ciphertext with size {} and type {} : {}", ciphertext.size(), TEXT, to_hex(ciphertext.data(), ciphertext.size())));
        plaintext = decryptReceivedMessage(ciphertext);
        std::cout << "Plaintext: ";
        for (unsigned char c : plaintext) {
            std::cout << c;
        }
        std::cout << std::endl;
        if (sendACK(plaintext.data(), plaintext.size(), TEXT)) {
            std::cout << "Failed to send ACK";
            return -1;
        }
    } else if (myMessageHeader.messageType == IMAGE) {
        // Resize ciphertext buffer to fit the incoming image data
        ciphertext.resize(myMessageHeader.bit_length + crypto_auth_BYTES + crypto_secretbox_MACBYTES);

        r = recv(cur_socket, ciphertext.data(), ciphertext.size(), MSG_WAITALL);
        if (r != (ssize_t)ciphertext.size()) {
            std::cerr << "Failed to receive full image ciphertext\n";
            close(cur_socket);
            return -1;
        }
        logConnectionInfo(std::format("received ciphertext with size {} and type {} : {}", ciphertext.size(), IMAGE, to_hex(ciphertext.data(), ciphertext.size())));

        plaintext = decryptReceivedMessage(ciphertext);
        if (plaintext.empty()) {
            std::cerr << "Decryption failed for image data.\n";
            return -1;
        }

        // Save the image to disk
        std::string file_location = std::format("output/received_image{}.jpg", message_counter);
        std::ofstream outFile(file_location, std::ios::binary);
        if (!outFile) {
            std::cerr << "Failed to open file for writing image.\n";
            return -1;
        }
        outFile.write(reinterpret_cast<const char*>(plaintext.data()), plaintext.size());
        outFile.close();

        std::cout << "Image received and saved to 'output/received_image.jpg'\n";

        // Send ACK for image data
        if (sendACK(plaintext.data(), plaintext.size(), IMAGE)) {
            std::cerr << "Failed to send ACK for image\n";
            return -1;
        } else {
            std::cout << "Incorrect header, closing the socket";
            closeSocket();
            return 1;
        }
    }
    return 0;
}
std::vector<unsigned char> Connect::decryptReceivedMessage(std::vector<unsigned char> ciphertext) {
    // Decrypt
    std::vector<unsigned char> decrypted(ciphertext.size() - crypto_secretbox_MACBYTES);
    if (crypto_secretbox_open_easy(decrypted.data(), ciphertext.data(), ciphertext.size(), iv, rx) != 0) {
        std::cerr << "Decryption failed: tampered or corrupted data.\n";
        close(cur_socket);
        return {};
    }

    // Extract message and MAC
    if (decrypted.size() < crypto_auth_BYTES) {
        std::cerr << "Decrypted message too short.\n";
        return {};
    }

    size_t plaintext_len = decrypted.size() - crypto_auth_BYTES;
    std::vector<unsigned char> plaintext(decrypted.begin(), decrypted.begin() + plaintext_len);
    unsigned char received_mac[crypto_auth_BYTES];
    std::memcpy(received_mac, decrypted.data() + plaintext_len, crypto_auth_BYTES);

    // Verify MAC
    if (crypto_auth_verify(received_mac, decrypted.data(), plaintext_len, mac_key_in) != 0) {
        std::cerr << "MAC verification failed: message integrity compromised.\n";
        return {};
    }
    generateNonce();
    return plaintext;
}

int Connect::generateCommunicationKeys() {
    // Message counter
    message_counter = 1;

    // Create per-message nonce
    unsigned char nonce_input[2 * crypto_secretbox_NONCEBYTES + sizeof(message_counter)];

    // Mixing up the nonces
    if (handshake_initiator.nonce[0] > handshake_target.nonce[0]) {
        std::memcpy(nonce_input, handshake_initiator.nonce, crypto_secretbox_NONCEBYTES);
        std::memcpy(nonce_input + crypto_secretbox_NONCEBYTES, handshake_target.nonce, crypto_secretbox_NONCEBYTES);
    } else {
        std::memcpy(nonce_input, handshake_target.nonce, crypto_secretbox_NONCEBYTES);
        std::memcpy(nonce_input + crypto_secretbox_NONCEBYTES,  handshake_initiator.nonce, crypto_secretbox_NONCEBYTES);
    }
    std::memcpy(nonce_input + 2 * crypto_secretbox_NONCEBYTES, &message_counter, sizeof(message_counter));

    crypto_generichash(iv, sizeof(iv), nonce_input, sizeof(nonce_input), nullptr, 0);
    std::string formatted_iv;
    for (int i = 0; i < crypto_secretbox_NONCEBYTES; ++i) {
        formatted_iv += std::format("{:02x}", iv[i]);
    }
    std::cout << "IV nonce: " << formatted_iv << std::endl;

    // Derive MAC keys
    crypto_generichash(mac_key_in, sizeof(mac_key_in), rx, sizeof(rx), nullptr, 0);
    crypto_generichash(mac_key_out, sizeof(mac_key_out), tx, sizeof(tx), nullptr, 0);
    return 0;
}
int Connect::generateClientSessionKeys() {
    if (crypto_kx_client_session_keys(rx, tx, public_key, secret_key, handshake_target.public_key) != 0) {
        close(cur_socket);
        return -1;
    }
    return 0;
}
void Connect::generateNonce() {
    // Generate nonce
    randombytes_buf(handshake_initiator.nonce, sizeof(handshake_initiator.nonce));
    std::string formatted_nonce;
    for (int i = 0; i < crypto_kx_PUBLICKEYBYTES; ++i) {
        formatted_nonce += std::format("{:02x}", handshake_initiator.nonce[i]);
    }
    std::cout << "Nonce: " << formatted_nonce << std::endl;
}
int Connect::sendHandshake() {
    std::memcpy(handshake_initiator.signature, signed_response.signature, sizeof(handshake_initiator.signature));
    std::memcpy(handshake_initiator.identifier, identifier, sizeof(identifier));
    std::memcpy(handshake_initiator.public_key, public_key, sizeof(public_key));

    // Send the handshake
    ssize_t r = send(cur_socket, &handshake_initiator, sizeof(handshake_initiator), 0);
    if (r != sizeof(handshake_initiator)) {
        std::cerr << "Failed to send handshake\n";
        close(cur_socket);
        return -1;
    }
    logConnectionInfo(std::format("sent text with size {} and type {} : signature:{} identifier:{} publickey:{} nonce:{} ", sizeof(handshake_initiator), "HANDSHAKE", to_hex(handshake_initiator.signature, sizeof(handshake_initiator.signature)), to_hex(handshake_initiator.identifier, sizeof(handshake_initiator.identifier)), to_hex(handshake_initiator.public_key, sizeof(handshake_initiator.public_key)), to_hex(handshake_initiator.nonce, sizeof(handshake_initiator.nonce))));
    return 0;
}
int Connect::receiveHandshake() {
    ssize_t r = recv(cur_socket, &handshake_target, sizeof(handshake_target), MSG_WAITALL);
    if (r != sizeof(handshake_target)) {
        std::cerr << "Failed to receive signature response\n";
        close(cur_socket);
        return -1;
    }
    logConnectionInfo(std::format("received text with size {} and type {} : signature:{} identifier:{} publickey:{} nonce:{} ", sizeof(handshake_target), "HANDSHAKE", to_hex(handshake_target.signature, sizeof(handshake_target.signature)), to_hex(handshake_target.identifier, sizeof(handshake_target.identifier)), to_hex(handshake_target.public_key, sizeof(handshake_target.public_key)), to_hex(handshake_target.nonce, sizeof(handshake_target.nonce))));

    unsigned char msg[MAX_ID_LEN + crypto_kx_PUBLICKEYBYTES];
    std::memcpy(msg, handshake_target.identifier, MAX_ID_LEN);
    std::memcpy(msg + MAX_ID_LEN, handshake_target.public_key, crypto_kx_PUBLICKEYBYTES);

    if (crypto_sign_verify_detached(handshake_target.signature, msg, sizeof(msg), signed_response.signer_pk) == 0) {
        std::cout << "User is verified: CA signed their identity + public key.\n";
    } else {
        std::cerr << "Invalid user: signature not trusted by the Authority.\n";
        return -1;
    }
    return 0;
}
int Connect::sendDigitalSignature(int serverSocket, unsigned char authority_pk[], unsigned char authority_sk[], size_t authority_pk_size) {
    int clientSocket = accept(serverSocket, nullptr, nullptr);

    SignRequest signRequest;
    ssize_t r = recv(clientSocket, &signRequest, sizeof(signRequest), MSG_WAITALL);
    logConnectionInfo(std::format("received sign request with size {} and type {} : identifier:{} publickey:{}", r, "NO TYPE", to_hex(signRequest.identifier, sizeof(signRequest.identifier)), to_hex(signRequest.public_key, sizeof(signRequest.public_key))));


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

    crypto_sign_detached(signed_response.signature, nullptr, msg, msg_len, authority_sk);
    memcpy(signed_response.signer_pk, authority_pk, authority_pk_size);


    // Send back the signature + signer's public key
    r = send(clientSocket, &signed_response, sizeof(signed_response), 0);
    if (r != sizeof(signed_response)) {
        std::cerr << "Failed to send signature response\n";
    } else {
        std::cout << "Sent signature to client\n";
    }
    logConnectionInfo(std::format("sent signed response with size {} and type {} : signature:{} signer_publickkey:{}", r, "NO TYPE", to_hex(signed_response.signature, sizeof(signed_response.signature)), to_hex(signed_response.signer_pk, sizeof(signed_response.signer_pk))));

    close(clientSocket);
    return 0;
}
int Connect::getDigitalSignature() {
    // creating socket
    int clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    // specifying address
    sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(AUTHORITY_PORT);
    serverAddress.sin_addr.s_addr = INADDR_ANY;

    // sending connection request
    if (connect(clientSocket, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) == -1) {
        std::cout << std::format("Error connecting to CA: {}", serverAddress.sin_addr.s_addr) << std::endl;
        return -1;
    }

    SignRequest signRequest;
    // Copy identifier and public key into the struct
    memcpy(signRequest.identifier, identifier, MAX_ID_LEN);
    memcpy(signRequest.public_key, public_key, sizeof(public_key));  // Assume user_pk_size ≤ MAX_PK_SIZE

    // Send the struct
    ssize_t r = send(clientSocket, &signRequest, sizeof(signRequest), 0);
    if (r != sizeof(signRequest)) {
        std::cerr << "Failed to receive signature response\n";
        close(clientSocket);
        return -1;
    }
    logConnectionInfo(std::format("sent sign request with size {} and type {} : identifier:{} publickey:{}", r, "NO TYPE", to_hex(signRequest.identifier, sizeof(signRequest.identifier)), to_hex(signRequest.public_key, sizeof(signRequest.public_key))));

    std::cout << std::format("Sent the identifier and public key!\n");


    r = recv(clientSocket, &signed_response, sizeof(signed_response), MSG_WAITALL);
    logConnectionInfo(std::format("received signed response with size {} and type {} : signature:{} signer_publickkey:{}", r, "NO TYPE", to_hex(signed_response.signature, sizeof(signed_response.signature)), to_hex(signed_response.signer_pk, sizeof(signed_response.signer_pk))));
    if (r != sizeof(signed_response)) {
        std::cerr << "Failed to receive signature response\n";
        close(clientSocket);
        return -1;
    }



    // closing socket
    close(clientSocket);
    return 0;
}
void Connect::logConnectionInfo(const std::string& text) {
    Logger::Log(std::format("Identifier : {} , Message counter : {}", std::string(identifier), message_counter) + " | " + text);
}
void Connect::setSocket(int socket) {
    this->cur_socket = socket;
}
void Connect::closeSocket() {
    close(cur_socket);
}
std::string Connect::to_hex(const unsigned char* data, size_t len) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; i++) {
        oss << std::setw(2) << static_cast<int>(data[i]);
    }
    return oss.str();
}

# Secure Device-to-Server Communication
CSE 4057 – Programming Assignment  
**Furkan Gökgöz (150120076) · Bora Duman (150121043) · Arda Öztürk (150121051)**

---

## 1. Project Overview
This project implements a simplified secure communication protocol between a simulated device (`user`) and a secure server (`server`), coordinated by a lightweight Certificate Authority (`authority`).  
All cryptographic operations leverage the [libsodium](https://github.com/jedisct1/libsodium) library in C++17.

- **Public Key Infrastructure**:  
  - Authority generates an Ed25519 (elliptic curve 25519 for signing messages) key pair to sign client and server certificates.  
  - `user` and `server` request certificates by sending their identifiers and public keys to `authority`.  
- **Handshake & Key Exchange**:  
  - Parties exchange signed certificates, nonces, and X25519 (Elliptic Curve Diffie–Hellman) public keys in a custom handshake.  
  - Certificates are verified with Ed25519 signatures.  
  - Shared session keys (rx/tx) are derived via `crypto_kx` (X25519 ECDH).  
- **Secure Messaging**:  
  - **Text**: HMAC (via `crypto_auth`) is applied to message headers and appended to plaintext; the combined buffer is encrypted with `crypto_secretbox_easy` (XSalsa20-Poly1305, symmetric cryptography using Salsa20 as a base not AES).  
  - **Images**: Device signs raw image bytes with Ed25519 (`crypto_sign_detached`), then encrypts the image+signature bundle with `crypto_secretbox_easy`, same as Text.  
  - **Acknowledgements**: After each receive, the server sends an encrypted ACK message following the same MAC + secretbox pattern.  

---

## 2. Components & Build

### 2.1 Binaries
| Binary     | Description                                                                 | Port              |
|------------|-----------------------------------------------------------------------------|-------------------|
| `authority`| Certificate Authority: listens on `AUTHORITY_PORT`, issues Ed25519-signed certificates | `AUTHORITY_PORT`  |
| `server`   | Secure server: listens on `SERVER_PORT`, performs handshake and message exchange | `SERVER_PORT`     |
| `user`     | Device simulator: connects to server, obtains certificate, performs handshake, sends text/images | —               |

---

## 3. Communication Protocol

### 3.1 Certificate Enrollment
1. **SignRequest** (`identifier + public_key`) sent from `user`/`server` to CA.  
2. **SignResponse** (`signature + signer_public_key`) returned by CA.  
3. Certificates are verified via `crypto_sign_verify_detached`.

### 3.2 Handshake & Key Exchange
1. Exchange **HandshakeMessage**:  
   - Fields: `identifier`, `public_key` (X25519), `nonce`, `signature` (CA-signed), `signer_public_key` (CA).  
2. Verify handshake signatures with Ed25519.  
3. Derive shared session keys (`rx`, `tx`) using `crypto_kx_client_session_keys` / `crypto_kx_server_session_keys`.

### 3.3 Encrypted Text Messaging
1. Construct a HeaderMessage with fields: messageType = TEXT and bit_length (size of the text message).
2. Serialize the header (without padding) into bytes.
3. Compute an HMAC-SHA256 (crypto_auth) over the serialized header bytes.
4. Append the HMAC tag to the header bytes forming [header || header_mac].
5. Encrypt this combined buffer with crypto_secretbox_easy using the symmetric tx key and a per-message nonce; send the ciphertext to the receiver.
6. Wait for and verify an ACK from the receiver confirming the header was received and decrypted successfully.
7. Encrypt the plaintext message data similarly:
8. Compute HMAC over the plaintext
9. Append HMAC to plaintext forming [plaintext || plaintext_mac]
10. Encrypt with crypto_secretbox_easy and send ciphertext.
11. Wait for and verify ACK for the encrypted message.
12. Receiver decrypts ciphertext, verifies internal MAC from crypto_secretbox_easy, then verifies appended HMAC over the decrypted plaintext/header before processing.

### 3.4 Encrypted Image Transfer
1. Read the image file fully into memory as raw bytes.
2. Construct a HeaderMessage with messageType = IMAGE and bit_length set to the image size in bytes.
3. Serialize the header, compute HMAC-SHA256 over it, append HMAC to form [header || header_mac].
4. Encrypt combined header+MAC with crypto_secretbox_easy and send ciphertext.
5. Wait for and verify ACK for header.
6. Compute HMAC over raw image bytes, append it to image data forming [image_bytes || image_mac].
7. Encrypt this combined buffer with crypto_secretbox_easy and send ciphertext.
8. Wait for and verify ACK for image data.
9. Receiver decrypts ciphertext, verifies internal MAC, then verifies appended HMAC before processing or saving image.

### 3.5 Acknowledgements
- After each successful receive (text or image), `server` sends back an encrypted ACK following the same MAC + secretbox procedure.

---

## 4. Logging
- All plaintext and ciphertext operations, with timestamps, identifiers, and message counters, are logged via the `Logger` module to:
  - `authority_log.txt`
  - `server_log.txt`
  - `user_log.txt`

---

## 5. Security Analysis

- **No Certificate Revocation**  
  - Even if a Certificate Authority (CA) signs a certificate, it can later be revoked (e.g. due to compromise). During the handshake add a check before accepting the peer's certificate.
- **Nonce Reuse**  
  - Could send a new nonce with every new message
- **Lack of Forward Secrecy Beyond Initial ECDH**  
  - Using one ECDH key exchange at the beginning and reuse the derived key forever, a future key compromise can reveal past messages. Periodic handshakes could help solve this problem.
- **Replay Attacks on Handshake**  
  - The handshake is vulnarable to replay attacks, it might be better to include session identifiers.  
- **MAC Timing Attacks**  
  - There is information to be deriven from the time spent on the code actions so it is better to use constant-time comparisons functions to remove this security hole.

---

## 6. Divisin of Labor
- **Furkan Gökgöz (150120076)**  
  - Implemented ECDH-based session key derivation, `connect` methods for send/receive, `crypto_secretbox` encryption/decryption, and HMAC header logic.  
- **Bora Duman (150121043)**  
  - Developed the CA (`authority.cpp`), certificate request/issue logic, and Ed25519 signature handling.  
- **Arda Öztürk (150121051)**  
  - Created the `Logger` module, integrated image serialization and signature verification, and led end-to-end testing and integration.

---

## 7. References
- [libsodium Documentation](https://libsodium.org)  

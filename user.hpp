#ifndef USER_H_
#define USER_H_

#include <cstddef>
#include <cstdint>
int getDigitalSignature(int clientSocket, const char* identifier, uint16_t id_len, unsigned char user_pk[], size_t user_pk_size);
#endif  // USER_H_

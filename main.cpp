#include <iostream>
#include <string.h>
#include "AES.h"

int main()
{
    AES::AES128 aes128;
    AES::AES192 aes192;
    AES::AES256 aes256;
    typedef unsigned char uint8_t;
    uint8_t key[32] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                       0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                       0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
    std::string encryptedMsg =  aes256.encrypt("msgsmsgsmsgsmsgsmsgsmsgs", key);
    std::string decryptedMsg = aes256.decrypt(encryptedMsg, key);
    std::cout << encryptedMsg << std::endl << std::endl;
    std::cout << decryptedMsg;
    return 0;
}

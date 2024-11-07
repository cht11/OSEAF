#pragma once
#include"head.h"



// need to add decryption code here (Corresponding encryption code in NeedEncry.py file)
PBYTE decrypt(PBYTE pBuffer, DWORD bSize, PBYTE pKey, DWORD kSize, PDWORD outDataSize) {
    // parameter specification:
    // pBuffer: pointer to the encrypted data
    // bSize: size of the encrypted data
    // pKey: pointer to the key
    // kSize: size of the key
    // outDataSize: pointer to the size of the decrypted data
    // return value: pointer to the decrypted data if successful, NULL if failed


    *outDataSize  = bSize;
    return pBuffer;
}

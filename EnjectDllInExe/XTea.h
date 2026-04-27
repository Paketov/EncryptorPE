#pragma once

#include <stdint.h>

#define XTEA_BLOCK_SIZE 16

uint32_t Xtea3_Data_Encrypt(char* inout, int len, uint32_t* key, uint32_t iv);

uint32_t Xtea3_Data_Decrypt(char* inout, int len, uint32_t* key, uint32_t iv);

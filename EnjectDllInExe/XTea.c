#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <windows.h>
#include "XTea.h"
#include "main.h"


#pragma code_seg(".vtxt")
#pragma data_seg(".vdt")


#define rol(a, n) _rotl((unsigned int)(a), (n))
//
//static inline int rol(int a, int n) {
//	return _rotl((unsigned int)a, n);
//}

static void xtea3_encipher(unsigned int num_rounds, uint32_t* v, uint32_t* k) {
	unsigned int i;
	uint32_t a, b, c, d, sum = 0, t, delta = 0x9E3779B9;
	sum = 0;
	a = v[0] + k[0];
	b = v[1] + k[1];
	c = v[2] + k[2];
	d = v[3] + k[3];
	for (i = 0; i < num_rounds; i++) {
		a += (((b << 4) + rol(k[(sum % 4) + 4], b)) ^
			(d + sum) ^ ((b >> 5) + rol(k[sum % 4], b >> 27)));
		sum += delta;
		c += (((d << 4) + rol(k[((sum >> 11) % 4) + 4], d)) ^
			(b + sum) ^ ((d >> 5) + rol(k[(sum >> 11) % 4], d >> 27)));
		t = a; a = b; b = c; c = d; d = t;
	}
	v[0] = a ^ k[4];
	v[1] = b ^ k[5];
	v[2] = c ^ k[6];
	v[3] = d ^ k[7];
}

static void xtea3_decipher(unsigned int num_rounds, uint32_t* v, uint32_t* k) {
	unsigned int i;
	uint32_t a, b, c, d, t, delta = 0x9E3779B9, sum = delta * num_rounds;
	d = v[3] ^ k[7];
	c = v[2] ^ k[6];
	b = v[1] ^ k[5];
	a = v[0] ^ k[4];
	for (i = 0; i < num_rounds; i++) {
		t = d; d = c; c = b; b = a; a = t;
		c -= (((d << 4) + rol(k[((sum >> 11) % 4) + 4], d)) ^
			(b + sum) ^ ((d >> 5) + rol(k[(sum >> 11) % 4], d >> 27)));
		sum -= delta;
		a -= (((b << 4) + rol(k[(sum % 4) + 4], b)) ^
			(d + sum) ^ ((b >> 5) + rol(k[sum % 4], b >> 27)));
	}
	v[3] = d - k[3];
	v[2] = c - k[2];
	v[1] = b - k[1];
	v[0] = a - k[0];
}

uint32_t Xtea3_Data_Encrypt(char* inout, int len, uint32_t* key, uint32_t iv) {
	//unsigned char dataArray[BLOCK_SIZE];
	uint32_t CTR = iv;
	for (char* m = inout + len - XTEA_BLOCK_SIZE; inout <= m;) {
		//ep_memcpy(dataArray, inout, BLOCK_SIZE);
		*((uint32_t*)inout) ^= CTR;
		CTR++;
		xtea3_encipher(32, inout /*(uint32_t*)dataArray*/, key);
		//ep_memcpy(inout, dataArray, BLOCK_SIZE);
		inout = inout + XTEA_BLOCK_SIZE;
	}
	return CTR;
}


uint32_t Xtea3_Data_Decrypt(char* inout, int len, uint32_t* key, uint32_t iv) {
	//unsigned char dataArray[BLOCK_SIZE];
	uint32_t CTR = iv;
	for (char* m = inout + len - XTEA_BLOCK_SIZE; inout <= m;) {
		//ep_memcpy(dataArray, inout, BLOCK_SIZE);
		xtea3_decipher(32, inout /*(uint32_t*)dataArray*/, key);
		*((uint32_t*)inout) ^= CTR;
		CTR++;
		//ep_memcpy(inout, dataArray, BLOCK_SIZE);
		inout = inout + XTEA_BLOCK_SIZE;
	}
	return CTR;
}

#pragma data_seg(pop)
#pragma code_seg(pop)

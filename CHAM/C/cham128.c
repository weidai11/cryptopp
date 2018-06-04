#include "cham.h"

long long int Power()
{
	long long int result = 1;
	result <<= W;
	return result;
};

uint32_t ROL32(uint32_t input, int k)
{
	uint32_t temp;
	temp = input;
	temp >>= (W - k);
	input <<= k;
	temp |= input;
	return temp;

	// 간략하게 => return (x << i) | (x >> (32 - i));
};

uint32_t ROR32(uint32_t input, int k)
{
	uint32_t temp;
	temp = input;
	temp <<= (W - k);
	input >>= k;
	temp |= input;
	return temp;
};

void cham128_setkey(void *in, void *out)
{
	int i;
	uint32_t *k = (uint32_t*)in;
	uint32_t *rk = (uint32_t*)out;

	for (i = 0; i < KW; i++) 
	{
		rk[i] = k[i] ^ ROL32(k[i], 1) ^ ROL32(k[i], 8);
		rk[(i + KW) ^ 1] = k[i] ^ ROL32(k[i], 1) ^ ROL32(k[i], 11);
	}
}

void cham128_encrypt(void *key, void *in)
{
	int i;
	uint32_t t;
	uint32_t *rk = (uint32_t*)key;
	uint32_t *x = (uint32_t*)in;

	for (i = 0; i < R; i++)
	{
		if (i % 2 == 0) {
			t = ROL32((x[0] ^ i) + ((ROL32(x[1], 1) ^ rk[i % (2 * KW)]) & 0xFFFFFFFF), 8);
		}
		else {
			t = ROL32((x[0] ^ i) + ((ROL32(x[1], 8) ^ rk[i % (2 * KW)]) & 0xFFFFFFFF), 1);
		}

		x[0] = x[1];
		x[1] = x[2];
		x[2] = x[3];
		x[3] = t;
	}
}

void cham128_decrypt(void *key, void *in)
{
	int i;
	uint32_t t;
	uint32_t *rk = (uint32_t*)key;
	uint32_t *x = (uint32_t*)in;

	for (i = R - 1; i >= 0; i--)
	{
		t = x[3];
		x[3] = x[2];
		x[2] = x[1];
		x[1] = x[0];

		if (i % 2 == 0) {
			x[0] = (ROR32(t, 8) - ((ROL32(x[1], 1) ^ rk[i % (2 * KW)]) & 0xFFFFFFFF)) ^ i;

		}
		else {
			x[0] = (ROR32(t, 1) - ((ROL32(x[1], 8) ^ rk[i % (2 * KW)]) & 0xFFFFFFFF)) ^ i;
		}
	}
}
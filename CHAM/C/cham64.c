#include "cham.h"

uint16_t ROL16(uint16_t input, int k)
{
	uint16_t temp;
	temp = input;
	temp >>= (W - k);
	input <<= k;
	temp |= input;
	return temp;
};

uint16_t ROR16(uint16_t input, int k)
{
	uint16_t temp;
	temp = input;
	temp <<= (W - k);
	input >>= k;
	temp |= input;
	return temp;
};

void cham64_setkey(void *in, void *out)
{
	int i;
	uint16_t *k = (uint16_t*)in;
	uint16_t *rk = (uint16_t*)out;

	for (i = 0; i < KW; i++) 
	{
		rk[i] = k[i] ^ ROL16(k[i], 1) ^ ROL16(k[i], 8);
		rk[(i + KW) ^ 1] = k[i] ^ ROL16(k[i], 1) ^ ROL16(k[i], 11);
	}
}

void cham64_encrypt(void *key, void *in)
{
	int i;
	uint16_t t;
	uint16_t *rk = (uint16_t*)key;
	uint16_t *x = (uint16_t*)in;

	for (i = 0; i < R; i++)
	{
		if (i % 2 == 0) {
//			t = ROL16((x[0] ^ i) + ((ROL16(x[1], 1) ^ rk[i % (2 * KW)]) % Power()), 8);
			t = ROL16((x[0] ^ i) + ((ROL16(x[1], 1) ^ rk[i % (2 * KW)]) & 0xFFFF), 8);
		}
		else {
//			t = ROL16((x[0] ^ i) + ((ROL16(x[1], 8) ^ rk[i % (2 * KW)]) % Power()), 1);
			t = ROL16((x[0] ^ i) + ((ROL16(x[1], 8) ^ rk[i % (2 * KW)]) & 0xFFFF), 1);
		}

		x[0] = x[1];
		x[1] = x[2];
		x[2] = x[3];
		x[3] = t;
	}
}

void cham64_decrypt(void *key, void *in)
{
	int i;
	uint16_t t;
	uint16_t *rk = (uint16_t*)key;
	uint16_t *x = (uint16_t*)in;

	for (i = R-1; i >= 0; i--)
	{
		t = x[3];
		x[3] = x[2];
		x[2] = x[1];
		x[1] = x[0];

		if (i % 2 == 0) {
//			x[0] = (ROR16(t, 8) - ((ROL16(x[1], 1) ^ rk[i % (2 * KW)]) % Power())) ^ i;
			x[0] = (ROR16(t, 8) - ((ROL16(x[1], 1) ^ rk[i % (2 * KW)]) & 0xFFFF)) ^ i;
		}			
		else {
//			x[0] = (ROR16(t, 1) - ((ROL16(x[1], 8) ^ rk[i % (2 * KW)]) % Power())) ^ i;
			x[0] = (ROR16(t, 1) - ((ROL16(x[1], 8) ^ rk[i % (2 * KW)]) & 0xFFFF)) ^ i;
		}
	}
}
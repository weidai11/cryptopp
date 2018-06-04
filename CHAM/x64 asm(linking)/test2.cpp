// test2.cpp : 콘솔 응용 프로그램에 대한 진입점을 정의합니다.
//

#include "stdafx.h"
#include <stdio.h>  
#include <intrin.h>  
#include <iostream>
#include <fstream>
#include <iomanip>

#pragma intrinsic(__rdtsc)  
using namespace std;
//extern "C" void hello_from_asm();
extern "C" void Setkey(uint16_t *, uint16_t *);
extern "C" void Setkey_128(uint32_t *, uint32_t *);
extern "C" void Setkey_256(uint32_t *, uint32_t *);

extern "C" void Encryption(uint16_t *, uint16_t *, uint16_t *);
extern "C" void Encryption_128(uint32_t *, uint32_t *, uint32_t *);
extern "C" void Encryption_256(uint32_t *, uint32_t *, uint32_t *);

extern "C" void Decryption(uint16_t *, uint16_t *, uint16_t *);
extern "C" void Decryption_128(uint32_t *, uint32_t *, uint32_t *);
extern "C" void Decryption_256(uint32_t *, uint32_t *, uint32_t *);

//인자로 들어온 텍스트를 출력해주는 함수
void print_bytes(char *s, uint16_t *p, int len) {
	int i;
	printf("%s : ", s);
	for (i = 0; i<len; i++) {
		printf("%04x ", p[i]);
	}
	putchar('\n');
}

void print_bytes_32(char *s, uint32_t *p, int len) {
	int i;
	printf("%s : ", s);
	for (i = 0; i<len; i++) {
		printf("%08x ", p[i]);
	}
	putchar('\n');
}


int main()
{
	uint16_t key[8] = { 0x0100, 0x0302, 0x0504, 0x0706, 0x0908, 0x0b0a, 0x0d0c, 0x0f0e };
	uint16_t RK[16];
	uint16_t PT[4] = { 0x1100, 0x3322, 0x5544, 0x7766 };
	uint16_t RCT[4];

	uint32_t key_128[4] = { 0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c };
	uint32_t key_256[8] = { 0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c, 0xf3f2f1f0, 0xf7f6f5f4, 0xfbfaf9f8, 0xfffefdfc };

	uint16_t RK_64[16];
	uint32_t RK_128[8];
	uint32_t RK_256[16];

	uint16_t CT_64[4];
	uint32_t CT_128[4];
	uint32_t CT_256[4];

	uint16_t PT_64[4] = { 0x1100, 0x3322, 0x5544, 0x7766 };
	uint32_t PT_128[4] = { 0x33221100, 0x77665544, 0xbbaa9988, 0xffeeddcc };

	uint16_t RCT_64[4];
	uint32_t RCT_128[4];
	uint32_t RCT_256[4];

	

	unsigned __int64 t1, t2, t3, t4;
	unsigned __int64 SS, EE, DD;

	SS = 0;
	EE = 0;
	DD = 0;
	ofstream outfile("CHAM_64_128.txt");
	outfile << setw(15)<<"----------CHAM-64/128----------" << endl;
	outfile << setw(15)<<"Setkey" << setw(15) << "Encryption" << setw(15) << "Decryption" << endl;

	for (int i = 0; i < 3000; i++)
	{
		t1 = __rdtsc();
		Setkey(key, RK_64);
		t2 = __rdtsc();
		Encryption(PT_64, CT_64, RK_64);
		t3 = __rdtsc();
		Decryption(CT_64, RCT_64, RK_64);
		t4 = __rdtsc();
		outfile << setw(15) << t2 - t1 << setw(15) << t3 - t2 << setw(15) << t4 - t3 << endl;
		SS += t2 - t1;
		EE += t3 - t2;
		DD += t4 - t3;
	}
	outfile << "---Mean time---" << endl;
	outfile << setw(15) << SS / 3000 << setw(15) << EE / 3000 << setw(15) << DD / 3000 << endl;
	outfile.close();

	SS = 0;
	EE = 0;
	DD = 0;
	ofstream outfile2("CHAM_128_128.txt");
	outfile2 <<  "----------CHAM-128/128----------" << endl;
	outfile2 << setw(15) << "Setkey" << setw(15) << "Encryption" << setw(15) << "Decryption" << endl;

	for (int i = 0; i < 3000; i++)
	{
		t1 = __rdtsc();
		Setkey_128(key_128, RK_128);
		t2 = __rdtsc();
		Encryption_128(PT_128, CT_128, RK_128);
		t3 = __rdtsc();
		Decryption_128(CT_128, RCT_128, RK_128);
		t4 = __rdtsc();

		outfile2 << setw(15) << t2 - t1 << setw(15) << t3 - t2 << setw(15) << t4 - t3 << endl;
		SS += t2 - t1;
		EE += t3 - t2;
		DD += t4 - t3;
	}
	outfile2 << "---Mean time---" << endl;
	outfile2 << setw(15) << SS / 3000 << setw(15) << EE / 3000 << setw(15) << DD / 3000 << endl;
	outfile2.close();

	SS = 0;
	EE = 0;
	DD = 0;
	ofstream file2("CHAM_128_256.txt");
	
	file2 << "----------CHAM-128/256----------" << endl;
	file2 << setw(15) << "Setkey" << setw(15) << "Encryption" << setw(15) << "Decryption" << endl;

	for (int i = 0; i < 3000; i++)
	{
		t1 = __rdtsc();
		Setkey_256(key_256, RK_256);
		t2 = __rdtsc();
		Encryption_256(PT_128, CT_256, RK_256);
		t3 = __rdtsc();
		Decryption_256(CT_256, RCT_256, RK_256);
		t4 = __rdtsc();

		file2 << setw(15) << t2 - t1 << setw(15) << t3 - t2 << setw(15) << t4 - t3 << endl;
		SS += t2 - t1;
		EE += t3 - t2;
		DD += t4 - t3;
	}
	file2 << "---Mean time---" << endl;
	file2 << setw(15) << SS / 3000 << setw(15) << EE / 3000 << setw(15) << DD / 3000 << endl;
	file2.close();


	//cout << "CHAM-64/128" << endl;
	//t1 = __rdtsc();
	//Setkey(key, RK_64);
	//t2 = __rdtsc();
	//Encryption(PT_64, CT_64, RK_64);
	//t3 = __rdtsc();
	//Decryption(CT_64, RCT_64, RK_64);
	//t4 = __rdtsc();


	//print_bytes("PT", PT_64, 4);
	//print_bytes("CT", CT_64, 4);
	//print_bytes("DT", RCT_64, 4);
	//cout << endl;
	//cout << "Setkey : " << t2 - t1 << endl;
	//cout << "Encryption : " << t3 - t2 << endl;
	//cout << "Decryption : " << t4 - t3 << endl<<endl;

	//cout << "CHAM-128/128" << endl;
	//t1 = __rdtsc();
	//Setkey_128(key_128, RK_128);
	//t2 = __rdtsc();
	//Encryption_128(PT_128, CT_128, RK_128);
	//t3 = __rdtsc();
	//Decryption_128(CT_128, RCT_128, RK_128);
	//t4 = __rdtsc();

	//print_bytes_32("PT", PT_128, 4);
	//print_bytes_32("CT", CT_128, 4);
	//print_bytes_32("DT", RCT_128, 4);
	//cout << endl;
	//cout << "Setkey : " << t2 - t1 << endl;
	//cout << "Encryption : " << t3 - t2 << endl;
	//cout << "Decryption : " << t4 - t3 << endl<<endl;

	//cout << "CHAM-128/256" << endl;
	//t1 = __rdtsc();
	//Setkey_256(key_256, RK_256);
	//t2 = __rdtsc();
	//Encryption_256(PT_128, CT_256, RK_256);
	//t3 = __rdtsc();
	//Decryption_256(CT_256, RCT_256, RK_256);
	//t4 = __rdtsc();

	//print_bytes_32("PT", PT_128, 4);
	//print_bytes_32("CT", CT_256, 4);
	//print_bytes_32("DT", RCT_256, 4);

	//cout << endl;

	//cout << "Setkey : " << t2 - t1 << endl;
	//cout << "Encryption : " << t3 - t2 << endl;
	//cout << "Decryption : " << t4 - t3 << endl;

	return 0;
}
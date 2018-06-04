void cham128_256_setkey(void *key, void *rk)
{
	__asm
	{
		mov esi, key	// key
		mov edi, rk // round key
		xor eax, eax // i = 0

	key_loop :
		mov ebx, [esi + eax * 4] // ebx = k[i]
		mov ecx, ebx
		mov edx, ebx
		rol ebx, 1		// ROL32(k[i], 1)
		rol ecx, 8		// ROL32(k[i], 8)
		xor edx, ebx	// k[i] ^ ROL32(k[i], 1)
		xor edx, ecx	// k[i] ^ ROL32(k[i], 1) ^ ROL32(k[i], 8)
		mov[edi + eax * 4], edx	// rk[i] = edx

		xor edx, ecx	// edx == k[i] ^ ROL32(k[i], 1)
		rol ecx, 3		// ROL32(k[i], 8) << 3 => ROL32(k[i], 11)
		xor edx, ecx	// k[i] ^ ROL32(k[i], 1) ^ ROL32(k[i], 11)
		lea ebx, [eax + 8] // 주소 복사 // KW == 8
		xor ebx, 1
		mov[edi + ebx * 4], edx // rk[(i+KW) ^ 1] = edx
		add al, 1
		cmp al, 8 // KW == 8
		jnz	key_loop
	}
}

void cham128_256_encrypt(void *key, void *in)
{
	__asm
	{
		pushad
		mov esi, [in]
		push esi

		mov ecx, [key]
		push ecx

		lodsd	// esi에서 DWORD(32bit)만큼 읽어 eax에 복사, esi 주소 이동
		xchg eax, ebp // x0 == ebp
		lodsd
		xchg eax, ebx // x1 == ebx
		lodsd
		xchg eax, edx // x2 == edx
		lodsd
		xchg eax, esi // x3 == esi
		xor eax, eax	// eax = 0

	loop_v0 :
		pop ecx
		mov edi, ecx
		push ecx
		jmp loop_v2

	loop_v1 :
		test al, 15	// (al&15==0)이면 (ZF=1)
		jz loop_v0	// jump if zero (ZF=1)

	loop_v2 :
		push eax	// save i
		mov cx, 0x0108
		test al, 1	// (al&1==0)이면 (ZF=1) => if((i%2) == 0)
		jnz loop_v3	// ZF=0 이면 loop_v3로
		xchg ch, cl

	loop_v3 :
		xor ebp, eax	// in[0] ^ i
		mov eax, ebx
		rol eax, cl		// i==even일때 cl=1, odd일때 cl=8 // ROL32(x[1], 1)
		xor eax, [edi]	// ROL32(x[1], 1) ^ rk[i]
		scasd		// 레지스터와 메모리 값 비교(edi dword만큼 이동 = rk[i+1])
		add ebp, eax	// (x[0] ^ i) + ((ROL32(x[1], 1) ^ rk[i % (2 * KW)]) & 0xFFFFFFFF)
		xchg cl, ch
		rol ebp, cl		// ROL32((x[0] ^ i) + ((ROL32(x[1], 1) ^ rk[i % (2 * KW)]) & 0xFFFFFFFF), 8)

		xchg ebp, ebx
		xchg ebx, edx
		xchg edx, esi

		pop eax
		add al, 1
		cmp al, 96 // ROUND == 96
		jnz loop_v1	//	ZF=0 이면 loop_v1

		pop ecx
		pop edi
		xchg eax, ebp
		stosd	// eax 값을 DWORD(32bit)만큼 읽어 edi 주소에 복사, edi 주소 이동
		xchg eax, ebx
		stosd
		xchg eax, edx
		stosd
		xchg eax, esi
		stosd
		popad
	}
}

void cham128_256_decrypt(void *key, void *in)
{
	__asm
	{
		pushad
		mov esi, [in]
		push esi

		mov ecx, [key]
		push ecx

		lodsd	// esi에서 DWORD(32bit)만큼 읽어 eax에 복사, esi 주소 이동
		xchg eax, ebp // x0 == ebp
		lodsd
		xchg eax, ebx // x1 == ebx
		lodsd
		xchg eax, edx // x2 == edx
		lodsd
		xchg eax, esi // x3 == esi
		mov eax, 95 // eax == ROUND -1

	loop_v0 :
		pop ecx
		mov edi, ecx
		push ecx
		jmp loop_v2

	loop_v1 :
		push eax
		and al, 15
		cmp al, 15
		pop eax
		je loop_v0

	loop_v2 :
		xchg esi, edx
		xchg edx, ebx
		xchg ebx, ebp
		push eax	// save i
		mov cx, 0x0108
		test al, 1	// (al&1==0)이면 (ZF=1) => if((i%2) == 0)
		jz loop_v3	// ZF==1 이면 loop_v3로
		xchg ch, cl

	loop_v3 :
		ror ebp, cl	// ROR32(t, 1)
		mov eax, ebx
		xchg cl, ch
		rol eax, cl		// i==even일때 cl=1, odd일때 cl=8 // ROL32(x[1], 8)
		xor eax, [edi + 4 * 15]	// ROL32(x[1], 8) ^ rk[i]
		std			// DF = 1, DF가 1이면 scasd 명령 시 edi 뒤로 이동
		scasd		// 레지스터와 메모리 값 비교(edi dword만큼 이동 = rk[i-1])
		sub ebp, eax	// ROR32(t ^ 8) - ((ROL32(x[1], 1) ^ rk[i % (2 * KW)]) & 0xFFFFFFFF)
		pop eax
		xor ebp, eax // (ROR32(t, 8) - ((ROL32(x[1], 1) ^ rk[i % (2 * KW)]) & 0xFFFFFFFF)) ^ i
		sub al, 1
		cmp al, -1
		jnz loop_v1	//	ZF=0 이면 loop_v1

		pop ecx
		pop edi
		cld		// DF = 0
		xchg eax, ebp
		stosd	// eax 값을 DWORD(32bit)만큼 읽어 edi 주소에 복사, edi 주소 이동
		xchg eax, ebx
		stosd
		xchg eax, edx
		stosd
		xchg eax, esi
		stosd
		popad
	}
}
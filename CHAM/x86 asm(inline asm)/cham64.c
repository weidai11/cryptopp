#include "cham64.h"

void cham64_setkey(void *key, void *rk)
{
	__asm
	{
		mov esi, key	// key
		mov edi, rk // round key
		xor eax, eax // i = 0

	key_loop :
		mov bx, [esi + eax * 2] // bx = k[i]
		mov cx, bx
		mov dx, bx

		rol bx, 1		// ROL16(k[i], 1)
		rol cx, 8		// ROL16(k[i], 8)
		xor dx, bx	// k[i] ^ ROL16(k[i], 1)
		xor dx, cx	// k[i] ^ ROL16(k[i], 1) ^ ROL16(k[i], 8)
		mov[edi + eax * 2], dx	// rk[i] = dx

		xor dx, cx	// k[i] ^ ROL16(k[i], 1)
		rol cx, 3	// ROL16(k[i], 8) << 3 => ROL16(k[i], 11)
		xor dx, cx	// k[i] ^ ROL16(k[i], 1) ^ ROL16(k[i], 11)
		lea ebx, [eax + 8] // 주소 복사
		xor bx, 1
		mov[edi + ebx * 2], dx // rk[(i+KW) ^ 1] = dx
		add al, 1
		cmp al, 8
		jnz	key_loop
	}
}

void cham64_encrypt(void *key, void *in)
{
	__asm
	{
		pushad
		mov esi, [in]
		push esi

		mov ecx, [key]
		push ecx

		lodsw	// esi에서 WORD(16bit)만큼 읽어 eax에 복사, esi 주소 이동
		xchg ax, bp // x0 == bp
		lodsw
		xchg ax, bx // x1 == bx
		lodsw
		xchg ax, dx // x2 == dx
		lodsw
		xchg ax, si // x3 == si
		xor ax, ax	// eax = 0

	loop_v0 :
		pop ecx
		mov edi, ecx
		push ecx
		jmp loop_v2

	loop_v1 :
		test al, 15	// (al&15==0)이면 (ZF=1)
		jz loop_v0	// jump if zero (ZF=1)

	loop_v2 :
		push ax	// save i
		mov cx, 0x0108
		test al, 1	// (al&1==0)이면 (ZF=1) => if((i%2) == 0)
		jnz loop_v3	// ZF=0 이면 loop_v3로
		xchg ch, cl

	loop_v3 :
		xor bp, ax	// in[0] ^ i
		mov ax, bx
		rol ax, cl		// i==even일때 cl=1, odd일때 cl=8 // ROL16(x[1], 1)
		xor ax, [edi]	// ROL16(x[1], 1) ^ rk[i]
		scasw		// 레지스터와 메모리 값 비교(edi word만큼 이동 = rk[i+1])
		add bp, ax	// (x[0] ^ i) + ((ROL16(x[1], 1) ^ rk[i % (2 * KW)]) & 0xFFFFFFFF)
		xchg cl, ch
		rol bp, cl		// ROL16((x[0] ^ i) + ((ROL16(x[1], 1) ^ rk[i % (2 * KW)]) & 0xFFFFFFFF), 8)

		xchg bp, bx
		xchg bx, dx
		xchg dx, si

		pop ax
		add al, 1
		cmp al, 80
		jnz loop_v1	//	ZF=0 이면 loop_v1

		pop ecx
		pop edi
		xchg ax, bp
		stosw	// eax 값을 WORD(16bit)만큼 읽어 edi 주소에 복사, edi 주소 이동
		xchg ax, bx
		stosw
		xchg ax, dx
		stosw
		xchg ax, si
		stosw
		popad
	}
}

void cham64_decrypt(void *key, void *in)
{
	__asm
	{
		pushad
		mov esi, [in]
		push esi

		mov ecx, [key]
		push ecx

		lodsw	// esi에서 WORD(16bit)만큼 읽어 eax에 복사, esi 주소 이동
		xchg ax, bp
		lodsw
		xchg ax, bx
		lodsw
		xchg ax, dx
		lodsw
		xchg ax, si
		mov ax, 79	// eax = R-1

	loop_v0 :
		pop ecx
		mov edi, ecx
		push ecx
		jmp loop_v2

	loop_v1 :
		push ax
		and al, 15
		cmp al, 15
		pop ax
		je loop_v0

	loop_v2 :
		xchg si, dx
		xchg dx, bx
		xchg bx, bp
		push ax	// save i
		mov cx, 0x0108
		test al, 1	// (al&1==0)이면 (ZF=1) => if((i%2) == 0)
		jz loop_v3	// ZF==1 이면 loop_v3로
		xchg ch, cl

	loop_v3 :
		ror bp, cl	// ROR16(t, 1)
		mov ax, bx
		xchg cl, ch
		rol ax, cl		// i==even일때 cl=1, odd일때 cl=8 // ROL16(x[1], 8)
		xor ax, [edi + 2 * 15]	// ROL16(x[1], 8) ^ rk[i]
		std			// DF = 1, DF가 1이면 scasd 명령 시 edi 뒤로 이동
		scasw		// 레지스터와 메모리 값 비교(edi word만큼 이동 = rk[i-1])
		sub bp, ax	// ROR16(t ^ 8) - ((ROL16(x[1], 1) ^ rk[i % (2 * KW)]) & 0xFFFFFFFF)
		pop ax
		xor bp, ax // (ROR16(t, 8) - ((ROL16(x[1], 1) ^ rk[i % (2 * KW)]) & 0xFFFFFFFF)) ^ i
		sub al, 1
		cmp al, -1
		jnz loop_v1	//	ZF=0 이면 loop_v1

		pop ecx
		pop edi
		cld		// DF = 0
		xchg ax, bp
		stosw	// eax 값을 WORD(16bit)만큼 읽어 edi 주소에 복사, edi 주소 이동
		xchg ax, bx
		stosw
		xchg ax, dx
		stosw
		xchg ax, si
		stosw
		popad
	}
}
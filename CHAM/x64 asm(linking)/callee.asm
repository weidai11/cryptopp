PUBLIC Setkey
PUBLIC Setkey_128
PUBLIC Setkey_256

PUBLIC Decryption
PUBLIC Decryption_128
PUBLIC Decryption_256

PUBLIC Encryption
PUBLIC Encryption_128
PUBLIC Encryption_256

.data
	K BYTE 128
	N BYTE 64
	R BYTE 80
	W BYTE 16
	KW BYTE 8

.code
Setkey PROC
    xor      eax, eax;      
    mov      esi, ecx;
    mov      edi, edx;
	push rbp
	mov rbp, rsp
key_loop:
    mov bx, [esi + eax * 2];
    mov ecx, ebx;
    mov edx, ebx;

    rol bx, 1; 
    rol cx, 8;
    xor dx, bx;
    xor dx, cx;

    mov [edi + eax * 2], dx;

    xor dx, cx;
    rol cx, 3; 
    xor dx, cx;

    lea ebx, [eax + 8];
    xor bx, 1;
    mov [edi + ebx*2], dx;
         
    inc al;
    cmp al, 8;
    jnz key_loop;

	mov rsp, rbp
	pop rbp
	ret

Setkey ENDP

Setkey_128 PROC
	xor      eax, eax;      
    mov      esi, ecx;
    mov      edi, edx;
	push rbp
	mov rbp, rsp

key_loop:
    mov ebx, [esi + eax * 4];
    mov ecx, ebx;
    mov edx, ebx;

    rol ebx, 1; 
    rol ecx, 8;
    xor edx, ebx;
    xor edx, ecx;

    mov [edi + eax * 4], edx;

    xor edx, ecx;
    rol ecx, 3; 
    xor edx, ecx;

    lea ebx, [eax + 4];
    xor ebx, 1;
    mov [edi + ebx*4], edx;
         
    inc al;
    cmp al, 4;
    jnz key_loop;

	mov rsp, rbp
	pop rbp
	ret

Setkey_128 ENDP


Setkey_256 PROC
	xor      eax, eax;      
    mov      esi, ecx;
    mov      edi, edx;
	push rbp
	mov rbp, rsp

key_loop:
    mov ebx, [esi + eax * 4];
    mov ecx, ebx;
    mov edx, ebx;

    rol ebx, 1; 
    rol ecx, 8;
    xor edx, ebx;
    xor edx, ecx;

    mov [edi + eax * 4], edx;

    xor edx, ecx;
    rol ecx, 3; 
    xor edx, ecx;

    lea ebx, [eax + 8];
    xor ebx, 1;
    mov [edi + ebx*4], edx;
         
    inc ax;
    cmp ax, 8;
    jnz key_loop;

	mov rsp, rbp
	pop rbp
	ret

Setkey_256 ENDP

Decryption PROC
		push rbp
		push rsp

		; r8->RK   /   ecx->esi->CT   / edx->r15->RCT
		mov rsi, rcx
		mov r15, rdx
		mov r9, 80
		
		mov rbx, [rsi]            ;// CT[i]값들을 읽어들임
		mov rcx, [rsi + 2]
		mov rdx, [rsi + 4]
		mov rax, [rsi + 6]

		;and rbx, 65535
		;and rcx, 65535
		;and rdx, 65535
		;and rax, 65535


	DEC_LOOP :

		sub r9, 1            ;// 시작은 79round임
		mov rsi, rax      ;//x_temp = x[3]
		mov rax, rdx      ;//x[3] = x[2]
		mov rdx, rcx      ;//x[2] = x[1]
		mov rcx, rbx      ;//x[1] = x[0]

		mov r11, rax		;//x1,2,3 백업
		mov r12, rdx
		mov r13, rcx
		
		test r9, 1     ; // 현재 라운드가 홀수이면 ODD로 jump
		jnz ODD
		; i(round)와 xor해서 더하는  부분은 64/128에서 의미없어서 지움
		ror si, 8
		rol cx, 1
		jmp FLOW

	ODD :
		ror si, 1
		rol cx, 8

	FLOW :
		mov rbp, r9
		and rbp, 15
		mov rbx, [r8 + 2 * rbp]   ;// RK[i % (2*KW)]

		xor cx, bx
		and rcx, 65535
		sub rsi, rcx

		mov rbx, rsi     ; // 포문 시작시 x[1] = x[0]때문에, ebx에다가 옮겼음
		xor rbx, r9       ; // 전체 연산 ^ i

		mov rax, r11		; // x1,2,3 복구
		mov rdx, r12
		mov rcx, r13

		cmp r9, 0       ;  // 마지막 라운드 아니면 다시 반복문
		jne DEC_LOOP

		mov[r15], bx
		mov[r15 + 2], cx
		mov[r15 + 4], dx
		mov[r15 + 6], ax

		pop rsp
		pop rbp
		ret

Decryption ENDP


Decryption_128 PROC
		push rbp
		push rsp

		; r8->RK   /   ecx->esi->CT   / edx->r15->RCT
		mov rsi, rcx
		mov r15, rdx
		mov r9, 80
		
		mov rbx, [rsi]            ;// CT[i]값들을 읽어들임
		mov rcx, [rsi + 4]
		mov rdx, [rsi + 8]
		mov rax, [rsi + 12]
		

	DEC_LOOP :
		sub r9, 1         ;// 시작은 79round임
		mov esi, eax      ;//x_temp = x[3]
		mov eax, edx      ;//x[3] = x[2]
		mov edx, ecx      ;//x[2] = x[1]
		mov ecx, ebx      ;//x[1] = x[0]

		mov r11, rax		;//x1,2,3 백업
		mov r12, rdx
		mov r13, rcx
		
		test r9, 1     ; // 현재 라운드가 홀수이면 ODD로 jump
		jnz ODD
		; i(round)와 xor해서 더하는  부분은 64/128에서 의미없어서 지움
		ror esi, 8
		rol ecx, 1
		jmp FLOW

	ODD :
		ror esi, 1
		rol ecx, 8

	FLOW :
		mov rbp, r9
		and rbp, 7
		mov rbx, [r8 + 4 * rbp]   ;// RK[i % (2*KW)]

		xor ecx, ebx
		sub rsi, rcx

		mov rbx, rsi     ; // 포문 시작시 x[1] = x[0]때문에, ebx에다가 옮겼음
		xor rbx, r9       ; // 전체 연산 ^ i

		mov rax, r11		; // x1,2,3 복구
		mov rdx, r12
		mov rcx, r13

		cmp r9, 0       ;  // 마지막 라운드 아니면 다시 반복문
		jne DEC_LOOP

		mov[r15], ebx
		mov[r15 + 4], ecx
		mov[r15 + 8], edx
		mov[r15 + 12], eax

		pop rsp
		pop rbp
		ret

Decryption_128 ENDP


Decryption_256 PROC
		push rbp
		push rsp

		; r8->RK   /   ecx->esi->CT   / edx->r15->RCT
		mov rsi, rcx
		mov r15, rdx
		mov r9, 96
		
		mov rbx, [rsi]            ;// CT[i]값들을 읽어들임
		mov rcx, [rsi + 4]
		mov rdx, [rsi + 8]
		mov rax, [rsi + 12]
		

	DEC_LOOP :
		sub r9, 1         ;// 시작은 79round임
		mov esi, eax      ;//x_temp = x[3]
		mov eax, edx      ;//x[3] = x[2]
		mov edx, ecx      ;//x[2] = x[1]
		mov ecx, ebx      ;//x[1] = x[0]

		mov r11, rax		;//x1,2,3 백업
		mov r12, rdx
		mov r13, rcx
		
		test r9, 1     ; // 현재 라운드가 홀수이면 ODD로 jump
		jnz ODD
		; i(round)와 xor해서 더하는  부분은 64/128에서 의미없어서 지움
		ror esi, 8
		rol ecx, 1
		jmp FLOW

	ODD :
		ror esi, 1
		rol ecx, 8

	FLOW :
		mov rbp, r9
		and rbp, 15
		mov rbx, [r8 + 4 * rbp]   ;// RK[i % (2*KW)]

		xor ecx, ebx
		sub rsi, rcx

		mov rbx, rsi     ; // 포문 시작시 x[1] = x[0]때문에, ebx에다가 옮겼음
		xor rbx, r9       ; // 전체 연산 ^ i

		mov rax, r11		; // x1,2,3 복구
		mov rdx, r12
		mov rcx, r13

		cmp r9, 0       ;  // 마지막 라운드 아니면 다시 반복문
		jne DEC_LOOP

		mov[r15], ebx
		mov[r15 + 4], ecx
		mov[r15 + 8], edx
		mov[r15 + 12], eax

		pop rsp
		pop rbp
		ret
Decryption_256 ENDP


Encryption PROC
	push rbp;
	push rsp;

	mov rsi, rcx;
	mov r15, rdx;
	lodsw;
	xchg ax, bp;
	lodsw;
	xchg ax, bx;
	lodsw;
	xchg ax, dx;
	lodsw;
	xchg ax, si;

	xor eax, eax;				// i = 0

	enc_loop:
		mov r14, rax;					//i 가 짝수일때
		xor bp, ax;
		and ax, 15;
		mov cx, [edi + eax * 2];
		mov ax, bx;
		rol ax, 1;
		xor ax, cx;
		add bp, ax;
		rol bp, 8;
		mov rax, r14;

		inc eax;					//i 가 홀수일때
		mov r14, rax;
		xor bx, ax;
		and ax, 15;
		mov cx, [edi + eax * 2];
		mov ax, dx;
		rol ax, 8;
		xor ax, cx;
		add bx, ax;
		rol bx, 1;
		mov rax, r14;

		xchg bp, dx;
		xchg bx, si;

		inc eax;
		cmp al, R;
		jnz enc_loop;

	mov[r15], bp;
	mov[r15 + 2], bx;
	mov[r15 + 4], dx;
	mov[r15 + 6], si;

	pop rsp;
	pop rbp;
	ret;

Encryption ENDP

Encryption_128 PROC
	push rbp;
	push rsp;

	mov rsi, rcx;
	mov r15, rdx;
	lodsd;
	xchg eax, ebp;
	lodsd;
	xchg eax, ebx;
	lodsd;
	xchg eax, edx;
	lodsd;
	xchg eax, esi;

	xor eax, eax;				// i = 0

	enc_loop:
		mov r14, rax;					//i 가 짝수일때
		xor ebp, eax;
		and eax, 7;
		mov ecx, [edi + eax * 4];
		mov eax, ebx;
		rol eax, 1;
		xor eax, ecx;
		add ebp, eax;
		rol ebp, 8;
		mov rax, r14;

		inc eax;					//i 가 홀수일때
		mov r14, rax;
		xor ebx, eax;
		and eax, 7;
		mov ecx, [edi + eax * 4];
		mov eax, edx;
		rol eax, 8;
		xor eax, ecx;
		add ebx, eax;
		rol ebx, 1;
		mov rax, r14;

		xchg ebp, edx;
		xchg ebx, esi;

		inc eax;
		cmp al, R;
		jnz enc_loop;

	mov[r15], ebp;
	mov[r15 + 4], ebx;
	mov[r15 + 8], edx;
	mov[r15 + 12], esi;

	pop rsp;
	pop rbp;
	ret;

Encryption_128 ENDP

Encryption_256 PROC
	push rbp;
	push rsp;

	mov rsi, rcx;
	mov r15, rdx;
	lodsd;
	xchg eax, ebp;
	lodsd;
	xchg eax, ebx;
	lodsd;
	xchg eax, edx;
	lodsd;
	xchg eax, esi;

	xor eax, eax;				// i = 0

	enc_loop:
		mov r14, rax;					//i 가 짝수일때
		xor ebp, eax;
		and eax, 15;
		mov ecx, [edi + eax * 4];
		mov eax, ebx;
		rol eax, 1;
		xor eax, ecx;
		add ebp, eax;
		rol ebp, 8;
		mov rax, r14;

		inc eax;					//i 가 홀수일때
		mov r14, rax;
		xor ebx, eax;
		and eax, 15;
		mov ecx, [edi + eax * 4];
		mov eax, edx;
		rol eax, 8;
		xor eax, ecx;
		add ebx, eax;
		rol ebx, 1;
		mov rax, r14;

		xchg ebp, edx;
		xchg ebx, esi;

		inc eax;
		cmp eax, 96;
		jnz enc_loop;

	mov[r15], ebp;
	mov[r15 + 4], ebx;
	mov[r15 + 8], edx;
	mov[r15 + 12], esi;

	pop rsp;
	pop rbp;
	ret;
Encryption_256 ENDP

END

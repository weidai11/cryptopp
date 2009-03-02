include ksamd64.inc
EXTERNDEF ?Te@rdtable@CryptoPP@@3PA_KA:FAR
EXTERNDEF ?g_cacheLineSize@CryptoPP@@3IA:FAR
.CODE

    ALIGN   8
Baseline_Add	PROC
	lea		rdx, [rdx+8*rcx]
	lea		r8, [r8+8*rcx]
	lea		r9, [r9+8*rcx]
	neg		rcx					; rcx is negative index
	jz		$1@Baseline_Add
	mov		rax,[r8+8*rcx]
	add		rax,[r9+8*rcx]
	mov		[rdx+8*rcx],rax
$0@Baseline_Add:
	mov		rax,[r8+8*rcx+8]
	adc		rax,[r9+8*rcx+8]
	mov		[rdx+8*rcx+8],rax
	lea		rcx,[rcx+2]			; advance index, avoid inc which causes slowdown on Intel Core 2
	jrcxz	$1@Baseline_Add		; loop until rcx overflows and becomes zero
	mov		rax,[r8+8*rcx]
	adc		rax,[r9+8*rcx]
	mov		[rdx+8*rcx],rax
	jmp		$0@Baseline_Add
$1@Baseline_Add:
	mov		rax, 0
	adc		rax, rax			; store carry into rax (return result register)
	ret
Baseline_Add ENDP

    ALIGN   8
Baseline_Sub	PROC
	lea		rdx, [rdx+8*rcx]
	lea		r8, [r8+8*rcx]
	lea		r9, [r9+8*rcx]
	neg		rcx					; rcx is negative index
	jz		$1@Baseline_Sub
	mov		rax,[r8+8*rcx]
	sub		rax,[r9+8*rcx]
	mov		[rdx+8*rcx],rax
$0@Baseline_Sub:
	mov		rax,[r8+8*rcx+8]
	sbb		rax,[r9+8*rcx+8]
	mov		[rdx+8*rcx+8],rax
	lea		rcx,[rcx+2]			; advance index, avoid inc which causes slowdown on Intel Core 2
	jrcxz	$1@Baseline_Sub		; loop until rcx overflows and becomes zero
	mov		rax,[r8+8*rcx]
	sbb		rax,[r9+8*rcx]
	mov		[rdx+8*rcx],rax
	jmp		$0@Baseline_Sub
$1@Baseline_Sub:
	mov		rax, 0
	adc		rax, rax			; store carry into rax (return result register)

	ret
Baseline_Sub ENDP

ALIGN   8
Rijndael_Enc_AdvancedProcessBlocks	PROC FRAME
rex_push_reg rsi
push_reg rdi
push_reg rbx
push_reg rbp
push_reg r12
.endprolog
mov r8, rcx
mov rsi, ?Te@rdtable@CryptoPP@@3PA_KA
mov rdi, QWORD PTR [?g_cacheLineSize@CryptoPP@@3IA]
mov rbp, [(r8+16*19)]
mov rax, 16
and rax, rbp
movdqa xmm3, XMMWORD PTR [rdx+16+rax]
movdqa [(r8+16*12)], xmm3
lea rax, [rdx+rax+2*16]
sub rax, rbp
label0:
movdqa xmm0, [rax+rbp]
movdqa XMMWORD PTR [(r8+0)+rbp], xmm0
add rbp, 16
cmp rbp, 16*12
jl label0
movdqa xmm4, [rax+rbp]
movdqa xmm1, [rdx]
mov r11d, [rdx+4*4]
mov ebx, [rdx+5*4]
mov ecx, [rdx+6*4]
mov edx, [rdx+7*4]
xor rax, rax
label9:
mov ebp, [rsi+rax]
add rax, rdi
mov ebp, [rsi+rax]
add rax, rdi
mov ebp, [rsi+rax]
add rax, rdi
mov ebp, [rsi+rax]
add rax, rdi
cmp rax, 2048
jl label9
lfence
test DWORD PTR [(r8+16*18+8)], 1
jz label8
mov rbp, [(r8+16*14)]
movdqa xmm2, [rbp]
pxor xmm2, xmm1
psrldq xmm1, 14
movd eax, xmm1
mov al, BYTE PTR [rbp+15]
mov r12d, eax
movd eax, xmm2
psrldq xmm2, 4
movd edi, xmm2
psrldq xmm2, 4
movzx ebp, al
xor r11d, DWORD PTR [rsi+8*rbp+(((0+3) MOD (4))+1)]
movzx ebp, ah
xor edx, DWORD PTR [rsi+8*rbp+(((1+3) MOD (4))+1)]
shr eax, 16
movzx ebp, al
xor ecx, DWORD PTR [rsi+8*rbp+(((2+3) MOD (4))+1)]
movzx ebp, ah
xor ebx, DWORD PTR [rsi+8*rbp+(((3+3) MOD (4))+1)]
mov eax, edi
movd edi, xmm2
psrldq xmm2, 4
movzx ebp, al
xor ebx, DWORD PTR [rsi+8*rbp+(((0+3) MOD (4))+1)]
movzx ebp, ah
xor r11d, DWORD PTR [rsi+8*rbp+(((1+3) MOD (4))+1)]
shr eax, 16
movzx ebp, al
xor edx, DWORD PTR [rsi+8*rbp+(((2+3) MOD (4))+1)]
movzx ebp, ah
xor ecx, DWORD PTR [rsi+8*rbp+(((3+3) MOD (4))+1)]
mov eax, edi
movd edi, xmm2
movzx ebp, al
xor ecx, DWORD PTR [rsi+8*rbp+(((0+3) MOD (4))+1)]
movzx ebp, ah
xor ebx, DWORD PTR [rsi+8*rbp+(((1+3) MOD (4))+1)]
shr eax, 16
movzx ebp, al
xor r11d, DWORD PTR [rsi+8*rbp+(((2+3) MOD (4))+1)]
movzx ebp, ah
xor edx, DWORD PTR [rsi+8*rbp+(((3+3) MOD (4))+1)]
mov eax, edi
movzx ebp, al
xor edx, DWORD PTR [rsi+8*rbp+(((0+3) MOD (4))+1)]
movzx ebp, ah
xor ecx, DWORD PTR [rsi+8*rbp+(((1+3) MOD (4))+1)]
shr eax, 16
movzx ebp, al
xor ebx, DWORD PTR [rsi+8*rbp+(((2+3) MOD (4))+1)]
psrldq xmm2, 3
mov eax, [(r8+16*12)+0*4]
mov edi, [(r8+16*12)+2*4]
mov r10d, [(r8+16*12)+3*4]
movzx ebp, cl
xor r10d, DWORD PTR [rsi+8*rbp+(((3+3) MOD (4))+1)]
movzx ebp, bl
xor edi, DWORD PTR [rsi+8*rbp+(((3+3) MOD (4))+1)]
movzx ebp, bh
xor r10d, DWORD PTR [rsi+8*rbp+(((2+3) MOD (4))+1)]
shr ebx, 16
movzx ebp, bl
xor eax, DWORD PTR [rsi+8*rbp+(((1+3) MOD (4))+1)]
movzx ebp, bh
mov ebx, DWORD PTR [rsi+8*rbp+(((0+3) MOD (4))+1)]
xor ebx, [(r8+16*12)+1*4]
movzx ebp, ch
xor eax, DWORD PTR [rsi+8*rbp+(((2+3) MOD (4))+1)]
shr ecx, 16
movzx ebp, dl
xor eax, DWORD PTR [rsi+8*rbp+(((3+3) MOD (4))+1)]
movzx ebp, dh
xor ebx, DWORD PTR [rsi+8*rbp+(((2+3) MOD (4))+1)]
shr edx, 16
movzx ebp, ch
xor edi, DWORD PTR [rsi+8*rbp+(((0+3) MOD (4))+1)]
movzx ebp, cl
xor ebx, DWORD PTR [rsi+8*rbp+(((1+3) MOD (4))+1)]
movzx ebp, dl
xor edi, DWORD PTR [rsi+8*rbp+(((1+3) MOD (4))+1)]
movzx ebp, dh
xor r10d, DWORD PTR [rsi+8*rbp+(((0+3) MOD (4))+1)]
movd ecx, xmm2
mov edx, r11d
mov [(r8+0)+3*4], r10d
mov [(r8+0)+0*4], eax
mov [(r8+0)+1*4], ebx
mov [(r8+0)+2*4], edi
jmp label5
label3:
mov r11d, [(r8+16*12)+0*4]
mov ebx, [(r8+16*12)+1*4]
mov ecx, [(r8+16*12)+2*4]
mov edx, [(r8+16*12)+3*4]
label8:
mov rax, [(r8+16*14)]
movdqu xmm2, [rax]
mov rbp, [(r8+16*14)+8]
movdqu xmm5, [rbp]
pxor xmm2, xmm1
pxor xmm2, xmm5
movd eax, xmm2
psrldq xmm2, 4
movd edi, xmm2
psrldq xmm2, 4
movzx ebp, al
xor r11d, DWORD PTR [rsi+8*rbp+(((0+3) MOD (4))+1)]
movzx ebp, ah
xor edx, DWORD PTR [rsi+8*rbp+(((1+3) MOD (4))+1)]
shr eax, 16
movzx ebp, al
xor ecx, DWORD PTR [rsi+8*rbp+(((2+3) MOD (4))+1)]
movzx ebp, ah
xor ebx, DWORD PTR [rsi+8*rbp+(((3+3) MOD (4))+1)]
mov eax, edi
movd edi, xmm2
psrldq xmm2, 4
movzx ebp, al
xor ebx, DWORD PTR [rsi+8*rbp+(((0+3) MOD (4))+1)]
movzx ebp, ah
xor r11d, DWORD PTR [rsi+8*rbp+(((1+3) MOD (4))+1)]
shr eax, 16
movzx ebp, al
xor edx, DWORD PTR [rsi+8*rbp+(((2+3) MOD (4))+1)]
movzx ebp, ah
xor ecx, DWORD PTR [rsi+8*rbp+(((3+3) MOD (4))+1)]
mov eax, edi
movd edi, xmm2
movzx ebp, al
xor ecx, DWORD PTR [rsi+8*rbp+(((0+3) MOD (4))+1)]
movzx ebp, ah
xor ebx, DWORD PTR [rsi+8*rbp+(((1+3) MOD (4))+1)]
shr eax, 16
movzx ebp, al
xor r11d, DWORD PTR [rsi+8*rbp+(((2+3) MOD (4))+1)]
movzx ebp, ah
xor edx, DWORD PTR [rsi+8*rbp+(((3+3) MOD (4))+1)]
mov eax, edi
movzx ebp, al
xor edx, DWORD PTR [rsi+8*rbp+(((0+3) MOD (4))+1)]
movzx ebp, ah
xor ecx, DWORD PTR [rsi+8*rbp+(((1+3) MOD (4))+1)]
shr eax, 16
movzx ebp, al
xor ebx, DWORD PTR [rsi+8*rbp+(((2+3) MOD (4))+1)]
movzx ebp, ah
xor r11d, DWORD PTR [rsi+8*rbp+(((3+3) MOD (4))+1)]
mov eax, r11d
add r8, [(r8+16*19)]
add r8, 4*16
jmp label2
label1:
mov ecx, r12d
mov edx, r11d
mov eax, [(r8+0)+0*4]
mov ebx, [(r8+0)+1*4]
xor cl, ch
and rcx, 255
label5:
add r12d, 1
xor edx, DWORD PTR [rsi+rcx*8+3]
movzx ebp, dl
xor ebx, DWORD PTR [rsi+8*rbp+(((3+3) MOD (4))+1)]
movzx ebp, dh
mov ecx, DWORD PTR [rsi+8*rbp+(((2+3) MOD (4))+1)]
shr edx, 16
xor ecx, [(r8+0)+2*4]
movzx ebp, dh
xor eax, DWORD PTR [rsi+8*rbp+(((0+3) MOD (4))+1)]
movzx ebp, dl
mov edx, DWORD PTR [rsi+8*rbp+(((1+3) MOD (4))+1)]
xor edx, [(r8+0)+3*4]
add r8, [(r8+16*19)]
add r8, 3*16
jmp label4
label2:
mov r10d, [(r8+0)-4*16+3*4]
mov edi, [(r8+0)-4*16+2*4]
movzx ebp, cl
xor r10d, DWORD PTR [rsi+8*rbp+(((3+3) MOD (4))+1)]
mov cl, al
movzx ebp, ah
xor edi, DWORD PTR [rsi+8*rbp+(((2+3) MOD (4))+1)]
shr eax, 16
movzx ebp, bl
xor edi, DWORD PTR [rsi+8*rbp+(((3+3) MOD (4))+1)]
movzx ebp, bh
xor r10d, DWORD PTR [rsi+8*rbp+(((2+3) MOD (4))+1)]
shr ebx, 16
movzx ebp, al
xor r10d, DWORD PTR [rsi+8*rbp+(((1+3) MOD (4))+1)]
movzx ebp, ah
mov eax, DWORD PTR [rsi+8*rbp+(((0+3) MOD (4))+1)]
movzx ebp, bl
xor eax, DWORD PTR [rsi+8*rbp+(((1+3) MOD (4))+1)]
movzx ebp, bh
mov ebx, DWORD PTR [rsi+8*rbp+(((0+3) MOD (4))+1)]
movzx ebp, ch
xor eax, DWORD PTR [rsi+8*rbp+(((2+3) MOD (4))+1)]
movzx ebp, cl
xor ebx, DWORD PTR [rsi+8*rbp+(((3+3) MOD (4))+1)]
shr ecx, 16
movzx ebp, dl
xor eax, DWORD PTR [rsi+8*rbp+(((3+3) MOD (4))+1)]
movzx ebp, dh
xor ebx, DWORD PTR [rsi+8*rbp+(((2+3) MOD (4))+1)]
shr edx, 16
movzx ebp, ch
xor edi, DWORD PTR [rsi+8*rbp+(((0+3) MOD (4))+1)]
movzx ebp, cl
xor ebx, DWORD PTR [rsi+8*rbp+(((1+3) MOD (4))+1)]
movzx ebp, dl
xor edi, DWORD PTR [rsi+8*rbp+(((1+3) MOD (4))+1)]
movzx ebp, dh
xor r10d, DWORD PTR [rsi+8*rbp+(((0+3) MOD (4))+1)]
mov ecx, edi
xor eax, [(r8+0)-4*16+0*4]
xor ebx, [(r8+0)-4*16+1*4]
mov edx, r10d
label4:
mov r10d, [(r8+0)-4*16+7*4]
mov edi, [(r8+0)-4*16+6*4]
movzx ebp, cl
xor r10d, DWORD PTR [rsi+8*rbp+(((3+3) MOD (4))+1)]
mov cl, al
movzx ebp, ah
xor edi, DWORD PTR [rsi+8*rbp+(((2+3) MOD (4))+1)]
shr eax, 16
movzx ebp, bl
xor edi, DWORD PTR [rsi+8*rbp+(((3+3) MOD (4))+1)]
movzx ebp, bh
xor r10d, DWORD PTR [rsi+8*rbp+(((2+3) MOD (4))+1)]
shr ebx, 16
movzx ebp, al
xor r10d, DWORD PTR [rsi+8*rbp+(((1+3) MOD (4))+1)]
movzx ebp, ah
mov eax, DWORD PTR [rsi+8*rbp+(((0+3) MOD (4))+1)]
movzx ebp, bl
xor eax, DWORD PTR [rsi+8*rbp+(((1+3) MOD (4))+1)]
movzx ebp, bh
mov ebx, DWORD PTR [rsi+8*rbp+(((0+3) MOD (4))+1)]
movzx ebp, ch
xor eax, DWORD PTR [rsi+8*rbp+(((2+3) MOD (4))+1)]
movzx ebp, cl
xor ebx, DWORD PTR [rsi+8*rbp+(((3+3) MOD (4))+1)]
shr ecx, 16
movzx ebp, dl
xor eax, DWORD PTR [rsi+8*rbp+(((3+3) MOD (4))+1)]
movzx ebp, dh
xor ebx, DWORD PTR [rsi+8*rbp+(((2+3) MOD (4))+1)]
shr edx, 16
movzx ebp, ch
xor edi, DWORD PTR [rsi+8*rbp+(((0+3) MOD (4))+1)]
movzx ebp, cl
xor ebx, DWORD PTR [rsi+8*rbp+(((1+3) MOD (4))+1)]
movzx ebp, dl
xor edi, DWORD PTR [rsi+8*rbp+(((1+3) MOD (4))+1)]
movzx ebp, dh
xor r10d, DWORD PTR [rsi+8*rbp+(((0+3) MOD (4))+1)]
mov ecx, edi
xor eax, [(r8+0)-4*16+4*4]
xor ebx, [(r8+0)-4*16+5*4]
mov edx, r10d
add r8, 32
test r8, 255
jnz label2
sub r8, 16*16
movzx ebp, ch
movzx edi, BYTE PTR [rsi+rbp*8+1]
movzx ebp, dl
xor edi, DWORD PTR [rsi+rbp*8+0]
mov WORD PTR [(r8+16*13)+2], di
movzx ebp, dh
movzx edi, BYTE PTR [rsi+rbp*8+1]
movzx ebp, al
xor edi, DWORD PTR [rsi+rbp*8+0]
mov WORD PTR [(r8+16*13)+6], di
shr edx, 16
movzx ebp, ah
movzx edi, BYTE PTR [rsi+rbp*8+1]
movzx ebp, bl
xor edi, DWORD PTR [rsi+rbp*8+0]
mov WORD PTR [(r8+16*13)+10], di
shr eax, 16
movzx ebp, bh
movzx edi, BYTE PTR [rsi+rbp*8+1]
movzx ebp, cl
xor edi, DWORD PTR [rsi+rbp*8+0]
mov WORD PTR [(r8+16*13)+14], di
shr ebx, 16
movzx ebp, dh
movzx edi, BYTE PTR [rsi+rbp*8+1]
movzx ebp, al
xor edi, DWORD PTR [rsi+rbp*8+0]
mov WORD PTR [(r8+16*13)+12], di
shr ecx, 16
movzx ebp, ah
movzx edi, BYTE PTR [rsi+rbp*8+1]
movzx ebp, bl
xor edi, DWORD PTR [rsi+rbp*8+0]
mov WORD PTR [(r8+16*13)+0], di
movzx ebp, bh
movzx edi, BYTE PTR [rsi+rbp*8+1]
movzx ebp, cl
xor edi, DWORD PTR [rsi+rbp*8+0]
mov WORD PTR [(r8+16*13)+4], di
movzx ebp, ch
movzx edi, BYTE PTR [rsi+rbp*8+1]
movzx ebp, dl
xor edi, DWORD PTR [rsi+rbp*8+0]
mov WORD PTR [(r8+16*13)+8], di
mov rax, [(r8+16*14)+16]
mov rbx, [(r8+16*14)+24]
mov rcx, [(r8+16*18+8)]
sub rcx, 16
movdqu xmm2, [rax]
pxor xmm2, xmm4
movdqa xmm0, [(r8+16*16)+16]
paddq xmm0, [(r8+16*14)+16]
movdqa [(r8+16*14)+16], xmm0
pxor xmm2, [(r8+16*13)]
movdqu [rbx], xmm2
jle label7
mov [(r8+16*18+8)], rcx
test rcx, 1
jnz label1
movdqa xmm0, [(r8+16*16)]
paddd xmm0, [(r8+16*14)]
movdqa [(r8+16*14)], xmm0
jmp label3
label7:
mov rbp, [(r8+16*18)]
pop r12
pop rbp
pop rbx
pop rdi
pop rsi
ret
Rijndael_Enc_AdvancedProcessBlocks ENDP

ALIGN   8
GCM_AuthenticateBlocks_2K	PROC FRAME
rex_push_reg rsi
push_reg rdi
push_reg rbx
.endprolog
mov rsi, r8
mov r11, r9
movdqa xmm0, [rsi]
label0:
movdqu xmm4, [rcx]
pxor xmm0, xmm4
movd ebx, xmm0
mov eax, 0f0f0f0f0h
and eax, ebx
shl ebx, 4
and ebx, 0f0f0f0f0h
movzx edi, ah
movdqa xmm5, XMMWORD PTR [rsi + 32 + 1024 + rdi]
movzx edi, al
movdqa xmm4, XMMWORD PTR [rsi + 32 + 1024 + rdi]
shr eax, 16
movzx edi, ah
movdqa xmm3, XMMWORD PTR [rsi + 32 + 1024 + rdi]
movzx edi, al
movdqa xmm2, XMMWORD PTR [rsi + 32 + 1024 + rdi]
psrldq xmm0, 4
movd eax, xmm0
and eax, 0f0f0f0f0h
movzx edi, bh
pxor xmm5, XMMWORD PTR [rsi + 32 + (1-1)*256 + rdi]
movzx edi, bl
pxor xmm4, XMMWORD PTR [rsi + 32 + (1-1)*256 + rdi]
shr ebx, 16
movzx edi, bh
pxor xmm3, XMMWORD PTR [rsi + 32 + (1-1)*256 + rdi]
movzx edi, bl
pxor xmm2, XMMWORD PTR [rsi + 32 + (1-1)*256 + rdi]
movd ebx, xmm0
shl ebx, 4
and ebx, 0f0f0f0f0h
movzx edi, ah
pxor xmm5, XMMWORD PTR [rsi + 32 + 1024 + 1*256 + rdi]
movzx edi, al
pxor xmm4, XMMWORD PTR [rsi + 32 + 1024 + 1*256 + rdi]
shr eax, 16
movzx edi, ah
pxor xmm3, XMMWORD PTR [rsi + 32 + 1024 + 1*256 + rdi]
movzx edi, al
pxor xmm2, XMMWORD PTR [rsi + 32 + 1024 + 1*256 + rdi]
psrldq xmm0, 4
movd eax, xmm0
and eax, 0f0f0f0f0h
movzx edi, bh
pxor xmm5, XMMWORD PTR [rsi + 32 + (2-1)*256 + rdi]
movzx edi, bl
pxor xmm4, XMMWORD PTR [rsi + 32 + (2-1)*256 + rdi]
shr ebx, 16
movzx edi, bh
pxor xmm3, XMMWORD PTR [rsi + 32 + (2-1)*256 + rdi]
movzx edi, bl
pxor xmm2, XMMWORD PTR [rsi + 32 + (2-1)*256 + rdi]
movd ebx, xmm0
shl ebx, 4
and ebx, 0f0f0f0f0h
movzx edi, ah
pxor xmm5, XMMWORD PTR [rsi + 32 + 1024 + 2*256 + rdi]
movzx edi, al
pxor xmm4, XMMWORD PTR [rsi + 32 + 1024 + 2*256 + rdi]
shr eax, 16
movzx edi, ah
pxor xmm3, XMMWORD PTR [rsi + 32 + 1024 + 2*256 + rdi]
movzx edi, al
pxor xmm2, XMMWORD PTR [rsi + 32 + 1024 + 2*256 + rdi]
psrldq xmm0, 4
movd eax, xmm0
and eax, 0f0f0f0f0h
movzx edi, bh
pxor xmm5, XMMWORD PTR [rsi + 32 + (3-1)*256 + rdi]
movzx edi, bl
pxor xmm4, XMMWORD PTR [rsi + 32 + (3-1)*256 + rdi]
shr ebx, 16
movzx edi, bh
pxor xmm3, XMMWORD PTR [rsi + 32 + (3-1)*256 + rdi]
movzx edi, bl
pxor xmm2, XMMWORD PTR [rsi + 32 + (3-1)*256 + rdi]
movd ebx, xmm0
shl ebx, 4
and ebx, 0f0f0f0f0h
movzx edi, ah
pxor xmm5, XMMWORD PTR [rsi + 32 + 1024 + 3*256 + rdi]
movzx edi, al
pxor xmm4, XMMWORD PTR [rsi + 32 + 1024 + 3*256 + rdi]
shr eax, 16
movzx edi, ah
pxor xmm3, XMMWORD PTR [rsi + 32 + 1024 + 3*256 + rdi]
movzx edi, al
pxor xmm2, XMMWORD PTR [rsi + 32 + 1024 + 3*256 + rdi]
movzx edi, bh
pxor xmm5, XMMWORD PTR [rsi + 32 + 3*256 + rdi]
movzx edi, bl
pxor xmm4, XMMWORD PTR [rsi + 32 + 3*256 + rdi]
shr ebx, 16
movzx edi, bh
pxor xmm3, XMMWORD PTR [rsi + 32 + 3*256 + rdi]
movzx edi, bl
pxor xmm2, XMMWORD PTR [rsi + 32 + 3*256 + rdi]
movdqa xmm0, xmm3
pslldq xmm3, 1
pxor xmm2, xmm3
movdqa xmm1, xmm2
pslldq xmm2, 1
pxor xmm5, xmm2
psrldq xmm0, 15
movd rdi, xmm0
movzx eax, WORD PTR [r11 + rdi*2]
shl eax, 8
movdqa xmm0, xmm5
pslldq xmm5, 1
pxor xmm4, xmm5
psrldq xmm1, 15
movd rdi, xmm1
xor ax, WORD PTR [r11 + rdi*2]
shl eax, 8
psrldq xmm0, 15
movd rdi, xmm0
xor ax, WORD PTR [r11 + rdi*2]
movd xmm0, eax
pxor xmm0, xmm4
add rcx, 16
sub rdx, 1
jnz label0
movdqa [rsi], xmm0
pop rbx
pop rdi
pop rsi
ret
GCM_AuthenticateBlocks_2K ENDP

ALIGN   8
GCM_AuthenticateBlocks_64K	PROC FRAME
rex_push_reg rsi
push_reg rdi
.endprolog
mov rsi, r8
movdqa xmm0, [rsi]
label1:
movdqu xmm1, [rcx]
pxor xmm1, xmm0
pxor xmm0, xmm0
movd eax, xmm1
psrldq xmm1, 4
movzx edi, al
add rdi, rdi
pxor xmm0, [rsi + 32 + (0*4+0)*256*16 + rdi*8]
movzx edi, ah
add rdi, rdi
pxor xmm0, [rsi + 32 + (0*4+1)*256*16 + rdi*8]
shr eax, 16
movzx edi, al
add rdi, rdi
pxor xmm0, [rsi + 32 + (0*4+2)*256*16 + rdi*8]
movzx edi, ah
add rdi, rdi
pxor xmm0, [rsi + 32 + (0*4+3)*256*16 + rdi*8]
movd eax, xmm1
psrldq xmm1, 4
movzx edi, al
add rdi, rdi
pxor xmm0, [rsi + 32 + (1*4+0)*256*16 + rdi*8]
movzx edi, ah
add rdi, rdi
pxor xmm0, [rsi + 32 + (1*4+1)*256*16 + rdi*8]
shr eax, 16
movzx edi, al
add rdi, rdi
pxor xmm0, [rsi + 32 + (1*4+2)*256*16 + rdi*8]
movzx edi, ah
add rdi, rdi
pxor xmm0, [rsi + 32 + (1*4+3)*256*16 + rdi*8]
movd eax, xmm1
psrldq xmm1, 4
movzx edi, al
add rdi, rdi
pxor xmm0, [rsi + 32 + (2*4+0)*256*16 + rdi*8]
movzx edi, ah
add rdi, rdi
pxor xmm0, [rsi + 32 + (2*4+1)*256*16 + rdi*8]
shr eax, 16
movzx edi, al
add rdi, rdi
pxor xmm0, [rsi + 32 + (2*4+2)*256*16 + rdi*8]
movzx edi, ah
add rdi, rdi
pxor xmm0, [rsi + 32 + (2*4+3)*256*16 + rdi*8]
movd eax, xmm1
psrldq xmm1, 4
movzx edi, al
add rdi, rdi
pxor xmm0, [rsi + 32 + (3*4+0)*256*16 + rdi*8]
movzx edi, ah
add rdi, rdi
pxor xmm0, [rsi + 32 + (3*4+1)*256*16 + rdi*8]
shr eax, 16
movzx edi, al
add rdi, rdi
pxor xmm0, [rsi + 32 + (3*4+2)*256*16 + rdi*8]
movzx edi, ah
add rdi, rdi
pxor xmm0, [rsi + 32 + (3*4+3)*256*16 + rdi*8]
add rcx, 16
sub rdx, 1
jnz label1
movdqa [rsi], xmm0
pop rdi
pop rsi
ret
GCM_AuthenticateBlocks_64K ENDP

_TEXT ENDS
END

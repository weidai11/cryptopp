PUBLIC Baseline_Add
PUBLIC Baseline_Sub
.CODE
       ALIGN     8
Baseline_Add	PROC

	lea		rdx, [rdx+8*rcx]
	lea		r8, [r8+8*rcx]
	lea		r9, [r9+8*rcx]

	neg		rcx					; rcx is negative index
	test	rcx, 2				; this clears carry flag
	jz		$0@Baseline_Add
	sub		rcx, 2
	jmp		$1@Baseline_Add

$0@Baseline_Add:
	jrcxz	$2@Baseline_Add		; loop until rcx overflows and becomes zero
	mov		rax,[r8+8*rcx]
	adc		rax,[r9+8*rcx]
	mov		[rdx+8*rcx],rax
	mov		rax,[r8+8*rcx+8]
	adc		rax,[r9+8*rcx+8]
	mov		[rdx+8*rcx+8],rax
$1@Baseline_Add:
	mov		rax,[r8+8*rcx+16]
	adc		rax,[r9+8*rcx+16]
	mov		[rdx+8*rcx+16],rax
	mov		rax,[r8+8*rcx+24]
	adc		rax,[r9+8*rcx+24]
	mov		[rdx+8*rcx+24],rax

	lea		rcx,[rcx+4]			; advance index, avoid inc which causes slowdown on Intel Core 2
	jmp		$0@Baseline_Add

$2@Baseline_Add:
	mov		rax, 0
	setc	al					; store carry into rax (return result register)

	ret
Baseline_Add ENDP

       ALIGN     8
Baseline_Sub	PROC

	lea		rdx, [rdx+8*rcx]
	lea		r8, [r8+8*rcx]
	lea		r9, [r9+8*rcx]

	neg		rcx					; rcx is negative index
	test	rcx, 2				; this clears carry flag
	jz		$0@Baseline_Sub
	sub		rcx, 2
	jmp		$1@Baseline_Sub

$0@Baseline_Sub:
	jrcxz	$2@Baseline_Sub		; loop until rcx overflows and becomes zero
	mov		rax,[r8+8*rcx]
	sbb		rax,[r9+8*rcx]
	mov		[rdx+8*rcx],rax
	mov		rax,[r8+8*rcx+8]
	sbb		rax,[r9+8*rcx+8]
	mov		[rdx+8*rcx+8],rax
$1@Baseline_Sub:
	mov		rax,[r8+8*rcx+16]
	sbb		rax,[r9+8*rcx+16]
	mov		[rdx+8*rcx+16],rax
	mov		rax,[r8+8*rcx+24]
	sbb		rax,[r9+8*rcx+24]
	mov		[rdx+8*rcx+24],rax

	lea		rcx,[rcx+4]			; advance index, avoid inc which causes slowdown on Intel Core 2
	jmp		$0@Baseline_Sub

$2@Baseline_Sub:
	mov		rax, 0
	setc	al					; store carry into rax (return result register)

	ret
Baseline_Sub ENDP

_TEXT ENDS
END

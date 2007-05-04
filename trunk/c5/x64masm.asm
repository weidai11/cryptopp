PUBLIC Baseline_Add
PUBLIC Baseline_Sub
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

_TEXT ENDS
END

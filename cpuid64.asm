;; https://docs.microsoft.com/en-us/cpp/build/x64-calling-convention
;; The first four integer arguments are passed in registers.
;; Integer values are passed in left-to-right order in RCX,
;; RDX, R8, and R9, respectively. Arguments five and higher
;; are passed on the stack.

;; The registers RAX, RCX, RDX, R8, R9, R10, R11, XMM0-5,
;; and the upper portions of YMM0-15 and ZMM0-15 are
;; considered volatile and must be considered destroyed on
;; function calls.

.CODE

TITLE    CPU features source file
SUBTITLE Microsoft specific ASM code to utilize CPUID and XGETBV64 for down level Microsoft toolchains

;; http://www.agner.org/optimize/vectorclass/read.php?i=65
;; word64 Xgetbv(word32 ctrl)
;; ctrl = rcx

    ALIGN   8
XGETBV64	PROC FRAME
.endprolog
    ;; query
    DB  	0fh, 01h, 0d0h
    ;; xcr = (EDX << 32) | EAX
    and 	rax, 0ffffffffh
    shl 	rdx, 32
    or  	rax, rdx
    ret
XGETBV64	ENDP

;; word64 CpuId(word32 func, word32 subfunc, word32 output[4])
;; func = rcx
;; subfunc = rdx
;; output = r8

    ALIGN   8
CPUID64	PROC FRAME
    ;; preserve per ABI
    mov 	[rsp+8], rbx
.savereg 	rbx, 8
.endprolog
    ;; eax = func
    mov 	rax, rcx
    ;; ecx = subfunc
    mov 	rcx, rdx
    ;; query
    cpuid
    ;; save
    mov 	[r8+0],  eax
    mov 	[r8+4],  ebx
    mov 	[r8+8],  ecx
    mov 	[r8+12], edx
    ;; return value
    mov 	rax, 1
    ;; restore
    mov 	rbx, [rsp+8]
    ret
CPUID64	ENDP

_TEXT ENDS
END

;; rdrand.asm - written and placed in public domain by Jeffrey Walton and Uri Blumenthal.
;;              Copyright assigned to the Crypto++ project.

;; This ASM file provides RDRAND and RDSEED to downlevel Unix and Linux tool
;; chains. You will need a modern Nasm, however. You can also use it in place
;; of intrinsics. The routines below run a little faster than the intrinsic
;; based routines.

;; nasm -f elf32 rdrand.s -DX86 -g -o rdrand-x86.o
;; nasm -f elfx32 rdrand.s -DX32 -g -o rdrand-x32.o
;; nasm -f elf64 rdrand.s -DX64 -g -o rdrand-x64.o

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;; C/C++ Function prototypes
;;   X86, X32 and X64:
;;     extern "C" void NASM_RDRAND_GenerateBlock(byte* ptr, size_t size);
;;     extern "C" void NASM_RDSEED_GenerateBlock(byte* ptr, size_t size);

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

%ifdef X86             ;; Set via the command line
%define arg1    [esp+04h]
%define arg2    [esp+08h]
%define buffer  ecx
%define bsize   edx
%define lsize    dl    ;; Used for tail bytes, 1-byte constants
%define MWSIZE  04h    ;; machine word size

%elifdef X32           ;; Set via the command line
%define buffer  edi    ;; Linux ABI
%define bsize   esi    ;; Linux ABI
%define lsize    si
%define MWSIZE  04h    ;; machine word size

%elifdef X64           ;; Set via the command line
%ifdef CYGWIN          ;; Cygwin follows Windows ABI here, not Linux ABI
%define buffer  rcx    ;; Windows ABI
%define bsize   rdx    ;; Windows ABI
%define lsize    dx    ;; Used for tail bytes, 2-byte constants
%else
%define buffer  rdi    ;; Linux ABI
%define bsize   rsi    ;; Linux ABI
%define lsize    si    ;; Used for tail bytes, 2-byte constants
%endif
%define MWSIZE  08h    ;; machine word size

%else
%error Missing or unknown architecture
%endif

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;; Fixups

%ifdef DARWIN
%define NASM_RDRAND_GenerateBlock _NASM_RDRAND_GenerateBlock
%define NASM_RDSEED_GenerateBlock _NASM_RDSEED_GenerateBlock
%endif

%ifdef CYGWIN
%ifdef X86
%define NASM_RDRAND_GenerateBlock _NASM_RDRAND_GenerateBlock
%define NASM_RDSEED_GenerateBlock _NASM_RDSEED_GenerateBlock
%endif
%endif

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

%ifdef X86         ;; Set via the command line

global        NASM_RDRAND_GenerateBlock
section       .text
align         8

NASM_RDRAND_GenerateBlock:

.Load_Arguments:

    mov       buffer, arg1
    mov       bsize,  arg2

    ;; A block of 16-bytes appears to be optimal. Adding
    ;;   more rdrand calls degrades performance.
    cmp       bsize, 16
    jb        .GenerateBlock_4

.GenerateBlock_16:

.Call_RDRAND_EAX_4:
    rdrand    eax
    jnc       .Call_RDRAND_EAX_4
    mov       [buffer+0], eax

.Call_RDRAND_EAX_3:
    rdrand    eax
    jnc       .Call_RDRAND_EAX_3
    mov       [buffer+4], eax

.Call_RDRAND_EAX_2:
    rdrand    eax
    jnc       .Call_RDRAND_EAX_2
    mov       [buffer+8], eax

.Call_RDRAND_EAX_1:
    rdrand    eax
    jnc       .Call_RDRAND_EAX_1
    mov       [buffer+12], eax

    sub       bsize,  16
    add       buffer, 16

    cmp       bsize,  16
    jae       .GenerateBlock_16

              ;; Fewer than 16 bytes remain
.GenerateBlock_4:

    cmp       lsize, 0
    je        .GenerateBlock_Return

.Call_RDRAND_EAX_0:

    rdrand    eax
    jnc       .Call_RDRAND_EAX_0

    cmp       lsize, MWSIZE
    jb        .Partial_Machine_Word

.Full_Machine_Word:

    mov       [buffer], eax
    add       buffer,   MWSIZE
    sub       lsize,    MWSIZE

              ;; Continue
    jmp       .GenerateBlock_4

              ;; 1,2,3 bytes remain
.Partial_Machine_Word:

              ;; Test bit 1 to see if size is at least 2
    test      lsize, 2
    jz        .Bit_1_Not_Set

    mov       [buffer], ax
    shr       eax, 16
    add       buffer, 2

.Bit_1_Not_Set:

              ;; Test bit 0 to see if size is at least 1
    test      lsize, 1
    jz        .Bit_0_Not_Set

    mov       [buffer], al

.Bit_0_Not_Set:

              ;; We've hit all the bits

.GenerateBlock_Return:

    xor       eax, eax
    ret

%endif        ;; X86

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

%ifdef X64 or X32  ;; Set via the command line

global        NASM_RDRAND_GenerateBlock
section       .text
align         16

NASM_RDRAND_GenerateBlock:

    ;; No need for Load_Arguments due to fastcall

    ;; A block of 32-bytes appears to be optimal. Adding
    ;;   more rdrand calls degrades performance.
    cmp       bsize, 32
    jb        .GenerateBlock_8

.GenerateBlock_32:

.Call_RDRAND_RAX_4:
    rdrand    rax
    jnc       .Call_RDRAND_RAX_4
    mov       [buffer+0], rax

.Call_RDRAND_RAX_3:
    rdrand    rax
    jnc       .Call_RDRAND_RAX_3
    mov       [buffer+8], rax

.Call_RDRAND_RAX_2:
    rdrand    rax
    jnc       .Call_RDRAND_RAX_2
    mov       [buffer+16], rax

.Call_RDRAND_RAX_1:
    rdrand    rax
    jnc       .Call_RDRAND_RAX_1
    mov       [buffer+24], rax

    sub       bsize,  32
    add       buffer, 32

    cmp       bsize,  32
    jae       .GenerateBlock_32

              ;; Fewer than 32 bytes remain
.GenerateBlock_8:

    cmp       lsize, 0
    je        .GenerateBlock_Return

.Call_RDRAND_RAX_0:
    rdrand    rax
    jnc       .Call_RDRAND_RAX_0

    cmp       lsize, MWSIZE
    jb        .Partial_Machine_Word

.Full_Machine_Word:

    mov       [buffer], rax
    add       buffer,   MWSIZE
    sub       lsize,    MWSIZE

              ;; Continue
    jmp       .GenerateBlock_8

              ;; 1,2,3,4,5,6,7 bytes remain
.Partial_Machine_Word:

              ;; Test bit 2 to see if size is at least 4
    test      lsize, 4
    jz        .Bit_2_Not_Set

    mov       [buffer], eax
    shr       rax, 32
    add       buffer, 4

.Bit_2_Not_Set:

              ;; Test bit 1 to see if size is at least 2
    test      lsize, 2
    jz        .Bit_1_Not_Set

    mov       [buffer], ax
    shr       eax, 16
    add       buffer, 2

.Bit_1_Not_Set:

              ;; Test bit 0 to see if size is at least 1
    test      lsize, 1
    jz        .Bit_0_Not_Set

    mov       [buffer], al

.Bit_0_Not_Set:

              ;; We've hit all the bits

.GenerateBlock_Return:

    xor       rax, rax
    ret

%endif    ;; X64

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

%ifdef X86         ;; Set via the command line

global        NASM_RDSEED_GenerateBlock
section       .text
align         8

NASM_RDSEED_GenerateBlock:

.Load_Arguments:

    mov       buffer, arg1
    mov       bsize,  arg2

    ;; A block of 16-bytes appears to be optimal. Adding
    ;;   more rdrand calls degrades performance.
    cmp       bsize, 16
    jb        .GenerateBlock_4

.GenerateBlock_16:

.Call_RDSEED_EAX_4:
    rdseed    eax
    jnc       .Call_RDSEED_EAX_4
    mov       [buffer+0], eax

.Call_RDSEED_EAX_3:
    rdseed    eax
    jnc       .Call_RDSEED_EAX_3
    mov       [buffer+4], eax

.Call_RDSEED_EAX_2:
    rdseed    eax
    jnc       .Call_RDSEED_EAX_2
    mov       [buffer+8], eax

.Call_RDSEED_EAX_1:
    rdseed    eax
    jnc       .Call_RDSEED_EAX_1
    mov       [buffer+12], eax

    sub       bsize,  16
    add       buffer, 16

    cmp       bsize,  16
    jae       .GenerateBlock_16

              ;; Fewer than 16 bytes remain
.GenerateBlock_4:

    cmp       lsize, 0
    je        .GenerateBlock_Return

.Call_RDSEED_EAX_0:

    rdseed    eax
    jnc       .Call_RDSEED_EAX_0

    cmp       lsize, MWSIZE
    jb        .Partial_Machine_Word

.Full_Machine_Word:

    mov       [buffer], eax
    add       buffer,   MWSIZE
    sub       lsize,    MWSIZE

              ;; Continue
    jmp       .GenerateBlock_4

              ;; 1,2,3 bytes remain
.Partial_Machine_Word:

              ;; Test bit 1 to see if size is at least 2
    test      lsize, 2
    jz        .Bit_1_Not_Set

    mov       [buffer], ax
    shr       eax, 16
    add       buffer, 2

.Bit_1_Not_Set:

              ;; Test bit 0 to see if size is at least 1
    test      lsize, 1
    jz        .Bit_0_Not_Set

    mov       [buffer], al

.Bit_0_Not_Set:

              ;; We've hit all the bits

.GenerateBlock_Return:

    xor       eax, eax
    ret

%endif        ;; X86

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

%ifdef X64 or X32  ;; Set via the command line

global        NASM_RDSEED_GenerateBlock
section       .text
align         16

NASM_RDSEED_GenerateBlock:

    ;; No need for Load_Arguments due to fastcall

    ;; A block of 32-bytes appears to be optimal. Adding
    ;;   more rdrand calls degrades performance.
    cmp       bsize, 32
    jb        .GenerateBlock_8

.GenerateBlock_32:

.Call_RDSEED_RAX_4:
    rdseed    rax
    jnc       .Call_RDSEED_RAX_4
    mov       [buffer+0], rax

.Call_RDSEED_RAX_3:
    rdseed    rax
    jnc       .Call_RDSEED_RAX_3
    mov       [buffer+8], rax

.Call_RDSEED_RAX_2:
    rdseed    rax
    jnc       .Call_RDSEED_RAX_2
    mov       [buffer+16], rax

.Call_RDSEED_RAX_1:
    rdseed    rax
    jnc       .Call_RDSEED_RAX_1
    mov       [buffer+24], rax

    sub       bsize,  32
    add       buffer, 32

    cmp       bsize,  32
    jae       .GenerateBlock_32

              ;; Fewer than 32 bytes remain
.GenerateBlock_8:

    cmp       lsize, 0
    je        .GenerateBlock_Return

.Call_RDSEED_RAX_0:
    rdseed    rax
    jnc       .Call_RDSEED_RAX_0

    cmp       lsize, MWSIZE
    jb        .Partial_Machine_Word

.Full_Machine_Word:

    mov       [buffer], rax
    add       buffer,   MWSIZE
    sub       lsize,    MWSIZE

              ;; Continue
    jmp       .GenerateBlock_8

              ;; 1,2,3,4,5,6,7 bytes remain
.Partial_Machine_Word:

              ;; Test bit 2 to see if size is at least 4
    test      lsize, 4
    jz        .Bit_2_Not_Set

    mov       [buffer], eax
    shr       rax, 32
    add       buffer, 4

.Bit_2_Not_Set:

              ;; Test bit 1 to see if size is at least 2
    test      lsize, 2
    jz        .Bit_1_Not_Set

    mov       [buffer], ax
    shr       eax, 16
    add       buffer, 2

.Bit_1_Not_Set:

              ;; Test bit 0 to see if size is at least 1
    test      lsize, 1
    jz        .Bit_0_Not_Set

    mov       [buffer], al

.Bit_0_Not_Set:

              ;; We've hit all the bits

.GenerateBlock_Return:

    xor       rax, rax
    ret

%endif    ;; X64

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;; rdrand.asm - written and placed in public domain by Jeffrey Walton and Uri Blumenthal.
;;              Copyright assigned to the Crypto++ project.

;; This ASM file provides RDRAND and RDSEED to downlevel Unix and Linux tool
;; chains. You will need a modern Nasm, however. You can also use it in place
;; of intrinsics. The routines below run a little faster than the intrinsic
;; based routines.

;; nasm -f elf32 rdrand.S -DX86 -g -o rdrand-x86.o
;; nasm -f elfx32 rdrand.S -DX32 -g -o rdrand-x32.o
;; nasm -f elf64 rdrand.S -DX64 -g -o rdrand-x64.o

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
%ifdef CYGWIN          ;; Cygwin follows Windows ABI here, not Linux ABI
%define buffer  ecx
%define bsize   edx
%else
%define buffer  edi
%define bsize   esi
%endif
%define MWSIZE  04h    ;; machine word size

%elifdef X32           ;; Set via the command line
%define buffer  edi
%define bsize   esi
%define MWSIZE  04h    ;; machine word size

%elifdef X64           ;; Set via the command line
%ifdef CYGWIN          ;; Cygwin follows Windows ABI here, not Linux ABI
%define buffer  rcx
%define bsize   rdx
%else
%define buffer  rdi
%define bsize   rsi
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

%ifdef CYGWIN and X86
%define NASM_RDRAND_GenerateBlock _NASM_RDRAND_GenerateBlock
%define NASM_RDSEED_GenerateBlock _NASM_RDSEED_GenerateBlock
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

.GenerateBlock_Top:

    cmp       bsize, 0
    je        .GenerateBlock_Return

.Call_RDRAND_EAX_0:

    rdrand    eax
    jnc       .Call_RDRAND_EAX_0

.RDRAND_succeeded:

    cmp       bsize, MWSIZE
    jb        .Partial_Machine_Word

.Full_Machine_Word:

    mov       [buffer], eax
    add       buffer,   MWSIZE
    sub       bsize,    MWSIZE

              ;; Continue
    jmp       .GenerateBlock_Top

              ;; 1,2,3 bytes remain for X86
.Partial_Machine_Word:

              ;; Test bit 1 to see if size is at least 2
    test      bsize, 2
    jz        .Bit_1_Not_Set

    mov       [buffer], ax
    shr       eax, 16
    add       buffer, 2

.Bit_1_Not_Set:

              ;; Test bit 0 to see if size is at least 1
    test      bsize, 1
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

.GenerateBlock_Top:

    cmp       bsize, 0
    je        .GenerateBlock_Return

.Call_RDRAND_RAX_0:
    rdrand    rax
    jnc       .Call_RDRAND_RAX_0

    cmp       bsize, MWSIZE
    jb        .Partial_Machine_Word

.Full_Machine_Word:

    mov       [buffer], rax
    add       buffer,   MWSIZE
    sub       bsize,    MWSIZE

              ;; Continue
    jmp       .GenerateBlock_Top

              ;; 1,2,3,4,5,6,7 bytes remain
.Partial_Machine_Word:

              ;; Test bit 2 to see if size is at least 4
    test      bsize, 4
    jz        .Bit_2_Not_Set

    mov       [buffer], eax
    shr       rax, 32
    add       buffer, 4

.Bit_2_Not_Set:

              ;; Test bit 1 to see if size is at least 2
    test      bsize, 2
    jz        .Bit_1_Not_Set

    mov       [buffer], ax
    shr       eax, 16
    add       buffer, 2

.Bit_1_Not_Set:

              ;; Test bit 0 to see if size is at least 1
    test      bsize, 1
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

.GenerateBlock_Top:

    cmp       bsize, 0
    je        .GenerateBlock_Return

.Call_RDSEED_EAX_0:

    rdseed    eax
    jnc       .Call_RDSEED_EAX_0

.RDSEED_succeeded:

    cmp       bsize, MWSIZE
    jb        .Partial_Machine_Word

.Full_Machine_Word:

    mov       [buffer], eax
    add       buffer,   MWSIZE
    sub       bsize,    MWSIZE

              ;; Continue
    jmp       .GenerateBlock_Top

              ;; 1,2,3 bytes remain for X86
.Partial_Machine_Word:

              ;; Test bit 1 to see if size is at least 2
    test      bsize, 2
    jz        .Bit_1_Not_Set

    mov       [buffer], ax
    shr       eax, 16
    add       buffer, 2

.Bit_1_Not_Set:

              ;; Test bit 0 to see if size is at least 1
    test      bsize, 1
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

.GenerateBlock_Top:

    cmp       bsize, 0
    je        .GenerateBlock_Return

.Call_RDSEED_RAX_0:
    rdseed    rax
    jnc       .Call_RDSEED_RAX_0

    cmp       bsize, MWSIZE
    jb        .Partial_Machine_Word

.Full_Machine_Word:

    mov       [buffer], rax
    add       buffer,   MWSIZE
    sub       bsize,    MWSIZE

              ;; Continue
    jmp       .GenerateBlock_Top

              ;; 1,2,3,4,5,6,7 bytes remain
.Partial_Machine_Word:

              ;; Test bit 2 to see if size is at least 4
    test      bsize, 4
    jz        .Bit_2_Not_Set

    mov       [buffer], eax
    shr       rax, 32
    add       buffer, 4

.Bit_2_Not_Set:

              ;; Test bit 1 to see if size is at least 2
    test      bsize, 2
    jz        .Bit_1_Not_Set

    mov       [buffer], ax
    shr       eax, 16
    add       buffer, 2

.Bit_1_Not_Set:

              ;; Test bit 0 to see if size is at least 1
    test      bsize, 1
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

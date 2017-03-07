;; rdrand.asm - written and placed in public domain by Jeffrey Walton and Uri Blumenthal.
;;              Copyright assigned to the Crypto++ project.

;; This ASM file provides RDRAND and RDSEED to downlevel Unix and Linux tool chains.
;; Additionally, the inline assembly code produced by GCC and Clang is not that
;; impressive. However, using this code requires NASM and an edit to the GNUmakefile.

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

%ifdef X86 or X32   ;; Set via the command line

;; Arg1, byte* buffer
;; Arg2, size_t bsize

global       NASM_RDRAND_GenerateBlock
section      .text

%ifdef X86
align        8
cpu          486
%else
align        16
%endif

NASM_RDRAND_GenerateBlock:

%ifdef X86
%define arg1 [ebp+04h]
%define arg2 [ebp+08h]
%define MWSIZE 04h    ;; machine word size
%else
%define MWSIZE 08h    ;; machine word size
%endif

%define buffer edi
%define bsize  esi

%ifdef X86
.Load_Arguments:

    mov     buffer, arg1
    mov     bsize,  arg2
%endif

            ;; Top of While loop
.GenerateBlock_Top:

            ;; Check remaining size
    cmp     bsize, 0
    je      .GenerateBlock_Return

.Call_RDRAND:
%ifdef X86
.Call_RDRAND_EAX:
%else
.Call_RDRAND_RAX:
    DB      48h    ;; X32 can use the full register, issue the REX.w prefix
%endif
            ;; RDRAND is not available prior to VS2012. Just emit
            ;;   the byte codes using DB. This is `rdrand eax`.
    DB      0Fh, 07h, 0F0h

            ;; If CF=1, the number returned by RDRAND is valid.
            ;; If CF=0, a random number was not available.
    jnc     .Call_RDRAND

.RDRAND_succeeded:

    cmp     bsize, MWSIZE
    jb      .Partial_Machine_Word

.Full_Machine_Word:

%ifdef X32
    mov     [buffer+4], eax        ;; We can only move 4 at a time
    DB      048h                   ;; Combined, these result in
    shr     eax, 32                ;;   `shr rax, 32`
%endif

    mov     [buffer], eax
    add     buffer, MWSIZE         ;; No need for Intel Core 2 slow word workarounds,
    sub     bsize,  MWSIZE         ;;   like `lea buffer,[buffer+MWSIZE]` for faster adds

            ;; Continue
    jmp     .GenerateBlock_Top

            ;; 1,2,3 bytes remain for X86
            ;; 1,2,3,4,5,6,7 remain for X32
.Partial_Machine_Word:

%ifdef X32
            ;; Test bit 2 to see if size is at least 4
    test    bsize, 4
    jz      .Bit_2_Not_Set

    mov     [buffer], eax
    add     buffer, 4

    DB      048h            ;; Combined, these result in
    shr     eax, 32         ;;   `shr rax, 32`

.Bit_2_Not_Set:
%endif

            ;; Test bit 1 to see if size is at least 2
    test    bsize, 2
    jz      .Bit_1_Not_Set

    mov     [buffer], ax
    shr     eax, 16
    add     buffer, 2

.Bit_1_Not_Set:

            ;; Test bit 0 to see if size is at least 1
    test    bsize, 1
    jz      .Bit_0_Not_Set

    mov     [buffer], al

.Bit_0_Not_Set:

            ;; We've hit all the bits

.GenerateBlock_Return:

    xor     eax, eax
    ret

%endif      ;; X86 and X32

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

%ifdef X64  ;; Set via the command line

global      NASM_RDRAND_GenerateBlock
section     .text
align       16

;; Arg1, byte* buffer
;; Arg2, size_t bsize

NASM_RDRAND_GenerateBlock:

%define MWSIZE  08h    ;; machine word size
%define buffer  rdi
%define bsize   rsi

    ;; No need for Load_Arguments due to fastcall

            ;; Top of While loop
.GenerateBlock_Top:

            ;; Check remaining size
    cmp     bsize, 0
    je      .GenerateBlock_Return

.Call_RDRAND_RAX:
            ;; RDRAND is not available prior to VS2012. Just emit
            ;;   the byte codes using DB. This is `rdrand rax`.
    DB      048h, 0Fh, 0C7h, 0F0h

            ;; If CF=1, the number returned by RDRAND is valid.
            ;; If CF=0, a random number was not available.
    jnc     .Call_RDRAND_RAX

.RDRAND_succeeded:

    cmp     bsize, MWSIZE
    jb      .Partial_Machine_Word

.Full_Machine_Word:

    mov     [buffer], rax
    add     buffer, MWSIZE
    sub     bsize, MWSIZE

            ;; Continue
    jmp     .GenerateBlock_Top

            ;; 1,2,3,4,5,6,7 bytes remain
.Partial_Machine_Word:

            ;; Test bit 2 to see if size is at least 4
    test    bsize, 4
    jz      .Bit_2_Not_Set

    mov     [buffer], eax
    shr     rax, 32
    add     buffer, 4

.Bit_2_Not_Set:

            ;; Test bit 1 to see if size is at least 2
    test    bsize, 2
    jz      .Bit_1_Not_Set

    mov     [buffer], ax
    shr     eax, 16
    add     buffer, 2

.Bit_1_Not_Set:

            ;; Test bit 0 to see if size is at least 1
    test    bsize, 1
    jz      .Bit_0_Not_Set

    mov     [buffer], al

.Bit_0_Not_Set:

            ;; We've hit all the bits

.GenerateBlock_Return:

    xor     rax, rax
    ret

%endif    ;; X64

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

%ifdef X86 or X32   ;; Set via the command line

;; Arg1, byte* buffer
;; Arg2, size_t bsize

global      NASM_RDSEED_GenerateBlock
section     .text
align       8

%ifdef X86
align       8
cpu         486
%else
align       16
%endif

NASM_RDSEED_GenerateBlock:

%ifdef X86
%define arg1 [ebp+04h]
%define arg2 [ebp+08h]
%define MWSIZE 04h    ;; machine word size
%else
%define MWSIZE 08h    ;; machine word size
%endif

%define buffer edi
%define bsize  esi

%ifdef X86
.Load_Arguments:

    mov     buffer, arg1
    mov     bsize,  arg2
%endif

            ;; Top of While loop
.GenerateBlock_Top:

            ;; Check remaining size
    cmp     bsize, 0
    je      .GenerateBlock_Return

.Call_RDSEED:
%ifdef X86
.Call_RDSEED_EAX:
%else
.Call_RDSEED_RAX:
    DB      48h        ;; X32 can use the full register, issue the REX.w prefix
%endif
            ;; RDSEED is not available prior to VS2012. Just emit
            ;;   the byte codes using DB. This is `rdseed eax`.
    DB      0Fh, 0C7h, 0F8h

            ;; If CF=1, the number returned by RDSEED is valid.
            ;; If CF=0, a random number was not available.
    jnc     .Call_RDSEED

.RDSEED_succeeded:

    cmp     bsize, MWSIZE
    jb      .Partial_Machine_Word

.Full_Machine_Word:

    mov     [buffer], eax
    add     buffer, MWSIZE        ;; No need for Intel Core 2 slow word workarounds,
    sub     bsize,  MWSIZE        ;;   like `lea buffer,[buffer+MWSIZE]` for faster adds

            ;; Continue
    jmp     .GenerateBlock_Top

            ;; 1,2,3 bytes remain for X86
            ;; 1,2,3,4,5,6,7 remain for X32
.Partial_Machine_Word:

%ifdef X32
            ;; Test bit 2 to see if size is at least 4
    test    bsize, 4
    jz      .Bit_2_Not_Set

    mov     [buffer], eax
    add     buffer, 4

    DB      048h            ;; Combined, these result in
    shr     eax, 32         ;;   `shr rax, 32`

.Bit_2_Not_Set:
%endif

            ;; Test bit 1 to see if size is at least 2
    test    bsize, 2
    jz      .Bit_1_Not_Set

    mov     [buffer], ax
    shr     eax, 16
    add     buffer, 2

.Bit_1_Not_Set:

            ;; Test bit 0 to see if size is at least 1
    test    bsize, 1
    jz      .Bit_0_Not_Set

    mov     [buffer], al

.Bit_0_Not_Set:

            ;; We've hit all the bits

.GenerateBlock_Return:

    xor     eax, eax
    ret

%endif    ;; X86 and X32

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

%ifdef X64  ;; Set via the command line

global      NASM_RDSEED_GenerateBlock
section     .text
align       16

;; Arg1, byte* buffer
;; Arg2, size_t bsize

NASM_RDSEED_GenerateBlock:

%define MWSIZE  08h    ;; machine word size
%define buffer  rdi
%define bsize   rsi

    ;; No need for Load_Arguments due to fastcall

            ;; Top of While loop
.GenerateBlock_Top:

            ;; Check remaining size
    cmp     bsize, 0
    je      .GenerateBlock_Return

.Call_RDSEED_RAX:
            ;; RDSEED is not available prior to VS2012. Just emit
            ;;   the byte codes using DB. This is `rdseed rax`.
    DB      048h, 0Fh, 0C7h, 0F8h

            ;; If CF=1, the number returned by RDSEED is valid.
            ;; If CF=0, a random number was not available.
    jnc     .Call_RDSEED_RAX

.RDSEED_succeeded:

    cmp     bsize, MWSIZE
    jb      .Partial_Machine_Word

.Full_Machine_Word:

    mov     [buffer], rax
    add     buffer, MWSIZE
    sub     bsize, MWSIZE

            ;; Continue
    jmp     .GenerateBlock_Top

            ;; 1,2,3,4,5,6,7 bytes remain
.Partial_Machine_Word:

            ;; Test bit 2 to see if size is at least 4
    test    bsize, 4
    jz      .Bit_2_Not_Set

    mov     [buffer], eax
    shr     rax, 32
    add     buffer, 4

.Bit_2_Not_Set:

            ;; Test bit 1 to see if size is at least 2
    test    bsize, 2
    jz      .Bit_1_Not_Set

    mov     [buffer], ax
    shr     eax, 16
    add     buffer, 2

.Bit_1_Not_Set:

            ;; Test bit 0 to see if size is at least 1
    test    bsize, 1
    jz      .Bit_0_Not_Set

    mov     [buffer], al

.Bit_0_Not_Set:

            ;; We've hit all the bits

.GenerateBlock_Return:

    xor     rax, rax
    ret

%endif      ;; _M_X64

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

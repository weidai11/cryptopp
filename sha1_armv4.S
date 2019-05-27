@ Copyright 2007-2019 The OpenSSL Project Authors. All Rights Reserved.
@
@ ====================================================================
@ Written by Andy Polyakov <appro@openssl.org> for the OpenSSL
@ project. The module is, however, dual licensed under OpenSSL and
@ CRYPTOGAMS licenses depending on where you obtain it. For further
@ details see http://www.openssl.org/~appro/cryptogams/.
@ ====================================================================

@ JW, MAY 2019: Begin defines from taken from arm_arch.h
@               The defines were included through the header.

# if !defined(__ARM_ARCH__)
#  if defined(__CC_ARM)
#   define __ARM_ARCH__ __TARGET_ARCH_ARM
#   if defined(__BIG_ENDIAN)
#    define __ARMEB__
#   else
#    define __ARMEL__
#   endif
#  elif defined(__GNUC__)
#   if   defined(__aarch64__)
#    define __ARM_ARCH__ 8
#    if __BYTE_ORDER__==__ORDER_BIG_ENDIAN__
#     define __ARMEB__
#    else
#     define __ARMEL__
#    endif

#   elif defined(__ARM_ARCH)
#    define __ARM_ARCH__ __ARM_ARCH
#   elif defined(__ARM_ARCH_8A__)
#    define __ARM_ARCH__ 8
#   elif defined(__ARM_ARCH_7__) || defined(__ARM_ARCH_7A__)     || \
        defined(__ARM_ARCH_7R__)|| defined(__ARM_ARCH_7M__)     || \
        defined(__ARM_ARCH_7EM__)
#    define __ARM_ARCH__ 7
#   elif defined(__ARM_ARCH_6__) || defined(__ARM_ARCH_6J__)     || \
        defined(__ARM_ARCH_6K__)|| defined(__ARM_ARCH_6M__)     || \
        defined(__ARM_ARCH_6Z__)|| defined(__ARM_ARCH_6ZK__)    || \
        defined(__ARM_ARCH_6T2__)
#    define __ARM_ARCH__ 6
#   elif defined(__ARM_ARCH_5__) || defined(__ARM_ARCH_5T__)     || \
        defined(__ARM_ARCH_5E__)|| defined(__ARM_ARCH_5TE__)    || \
        defined(__ARM_ARCH_5TEJ__)
#    define __ARM_ARCH__ 5
#   elif defined(__ARM_ARCH_4__) || defined(__ARM_ARCH_4T__)
#    define __ARM_ARCH__ 4
#   else
#    error "unsupported ARM architecture"
#   endif
#  endif
# endif

# if !defined(__ARM_MAX_ARCH__)
#  define __ARM_MAX_ARCH__ __ARM_ARCH__
# endif

# if __ARM_MAX_ARCH__<__ARM_ARCH__
#  error "__ARM_MAX_ARCH__ can't be less than __ARM_ARCH__"
# elif __ARM_MAX_ARCH__!=__ARM_ARCH__
#  if __ARM_ARCH__<7 && __ARM_MAX_ARCH__>=7 && defined(__ARMEB__)
#   error "can't build universal big-endian binary"
#  endif
# endif

# define ARMV7_NEON      (1<<0)

@ JW, MAY 2019: End defines from taken from arm_arch.h
@               Back to original Cryptogams code

#if defined(__thumb2__)
.syntax	unified
.thumb
#else
.code	32
#endif

.text

.align	5
.globl	sha1_block_data_order
.type	sha1_block_data_order,%function

sha1_block_data_order:
.Lsha1_block_data_order:

#if __ARM_ARCH__<7 && !defined(__thumb2__)
	sub	r3,pc,#8		@ sha1_block_data_order
#else
	adr	r3,.Lsha1_block_data_order
#endif

	stmdb	sp!,{r4,r5,r6,r7,r8,r9,r10,r11,r12,lr}
	add	r2,r1,r2,lsl#6	@ r2 to point at the end of r1
	ldmia	r0,{r3,r4,r5,r6,r7}

.Lloop:
	ldr	r8,.LK_00_19
	mov	r14,sp
	sub	sp,sp,#15*4
	mov	r5,r5,ror#30
	mov	r6,r6,ror#30
	mov	r7,r7,ror#30		@ [6]
.L_00_15:
#if __ARM_ARCH__<7
	ldrb	r10,[r1,#2]
	ldrb	r9,[r1,#3]
	ldrb	r11,[r1,#1]
	add	r7,r8,r7,ror#2			@ E+=K_00_19
	ldrb	r12,[r1],#4
	orr	r9,r9,r10,lsl#8
	eor	r10,r5,r6			@ F_xx_xx
	orr	r9,r9,r11,lsl#16
	add	r7,r7,r3,ror#27			@ E+=ROR(A,27)
	orr	r9,r9,r12,lsl#24
#else
	ldr	r9,[r1],#4			@ handles unaligned
	add	r7,r8,r7,ror#2			@ E+=K_00_19
	eor	r10,r5,r6			@ F_xx_xx
	add	r7,r7,r3,ror#27			@ E+=ROR(A,27)
#ifdef __ARMEL__
	rev	r9,r9				@ byte swap
#endif
#endif
	and	r10,r4,r10,ror#2
	add	r7,r7,r9			@ E+=X[i]
	eor	r10,r10,r6,ror#2		@ F_00_19(B,C,D)
	str	r9,[r14,#-4]!
	add	r7,r7,r10			@ E+=F_00_19(B,C,D)
#if __ARM_ARCH__<7
	ldrb	r10,[r1,#2]
	ldrb	r9,[r1,#3]
	ldrb	r11,[r1,#1]
	add	r6,r8,r6,ror#2			@ E+=K_00_19
	ldrb	r12,[r1],#4
	orr	r9,r9,r10,lsl#8
	eor	r10,r4,r5			@ F_xx_xx
	orr	r9,r9,r11,lsl#16
	add	r6,r6,r7,ror#27			@ E+=ROR(A,27)
	orr	r9,r9,r12,lsl#24
#else
	ldr	r9,[r1],#4			@ handles unaligned
	add	r6,r8,r6,ror#2			@ E+=K_00_19
	eor	r10,r4,r5			@ F_xx_xx
	add	r6,r6,r7,ror#27			@ E+=ROR(A,27)
#ifdef __ARMEL__
	rev	r9,r9				@ byte swap
#endif
#endif
	and	r10,r3,r10,ror#2
	add	r6,r6,r9			@ E+=X[i]
	eor	r10,r10,r5,ror#2		@ F_00_19(B,C,D)
	str	r9,[r14,#-4]!
	add	r6,r6,r10			@ E+=F_00_19(B,C,D)
#if __ARM_ARCH__<7
	ldrb	r10,[r1,#2]
	ldrb	r9,[r1,#3]
	ldrb	r11,[r1,#1]
	add	r5,r8,r5,ror#2			@ E+=K_00_19
	ldrb	r12,[r1],#4
	orr	r9,r9,r10,lsl#8
	eor	r10,r3,r4			@ F_xx_xx
	orr	r9,r9,r11,lsl#16
	add	r5,r5,r6,ror#27			@ E+=ROR(A,27)
	orr	r9,r9,r12,lsl#24
#else
	ldr	r9,[r1],#4			@ handles unaligned
	add	r5,r8,r5,ror#2			@ E+=K_00_19
	eor	r10,r3,r4			@ F_xx_xx
	add	r5,r5,r6,ror#27			@ E+=ROR(A,27)
#ifdef __ARMEL__
	rev	r9,r9				@ byte swap
#endif
#endif
	and	r10,r7,r10,ror#2
	add	r5,r5,r9			@ E+=X[i]
	eor	r10,r10,r4,ror#2		@ F_00_19(B,C,D)
	str	r9,[r14,#-4]!
	add	r5,r5,r10			@ E+=F_00_19(B,C,D)
#if __ARM_ARCH__<7
	ldrb	r10,[r1,#2]
	ldrb	r9,[r1,#3]
	ldrb	r11,[r1,#1]
	add	r4,r8,r4,ror#2			@ E+=K_00_19
	ldrb	r12,[r1],#4
	orr	r9,r9,r10,lsl#8
	eor	r10,r7,r3			@ F_xx_xx
	orr	r9,r9,r11,lsl#16
	add	r4,r4,r5,ror#27			@ E+=ROR(A,27)
	orr	r9,r9,r12,lsl#24
#else
	ldr	r9,[r1],#4			@ handles unaligned
	add	r4,r8,r4,ror#2			@ E+=K_00_19
	eor	r10,r7,r3			@ F_xx_xx
	add	r4,r4,r5,ror#27			@ E+=ROR(A,27)
#ifdef __ARMEL__
	rev	r9,r9				@ byte swap
#endif
#endif
	and	r10,r6,r10,ror#2
	add	r4,r4,r9			@ E+=X[i]
	eor	r10,r10,r3,ror#2		@ F_00_19(B,C,D)
	str	r9,[r14,#-4]!
	add	r4,r4,r10			@ E+=F_00_19(B,C,D)
#if __ARM_ARCH__<7
	ldrb	r10,[r1,#2]
	ldrb	r9,[r1,#3]
	ldrb	r11,[r1,#1]
	add	r3,r8,r3,ror#2			@ E+=K_00_19
	ldrb	r12,[r1],#4
	orr	r9,r9,r10,lsl#8
	eor	r10,r6,r7			@ F_xx_xx
	orr	r9,r9,r11,lsl#16
	add	r3,r3,r4,ror#27			@ E+=ROR(A,27)
	orr	r9,r9,r12,lsl#24
#else
	ldr	r9,[r1],#4			@ handles unaligned
	add	r3,r8,r3,ror#2			@ E+=K_00_19
	eor	r10,r6,r7			@ F_xx_xx
	add	r3,r3,r4,ror#27			@ E+=ROR(A,27)
#ifdef __ARMEL__
	rev	r9,r9				@ byte swap
#endif
#endif
	and	r10,r5,r10,ror#2
	add	r3,r3,r9			@ E+=X[i]
	eor	r10,r10,r7,ror#2		@ F_00_19(B,C,D)
	str	r9,[r14,#-4]!
	add	r3,r3,r10			@ E+=F_00_19(B,C,D)
#if defined(__thumb2__)
	mov	r12,sp
	teq	r14,r12
#else
	teq	r14,sp
#endif
	bne	.L_00_15		@ [((11+4)*5+2)*3]
	sub	sp,sp,#25*4
#if __ARM_ARCH__<7
	ldrb	r10,[r1,#2]
	ldrb	r9,[r1,#3]
	ldrb	r11,[r1,#1]
	add	r7,r8,r7,ror#2			@ E+=K_00_19
	ldrb	r12,[r1],#4
	orr	r9,r9,r10,lsl#8
	eor	r10,r5,r6			@ F_xx_xx
	orr	r9,r9,r11,lsl#16
	add	r7,r7,r3,ror#27			@ E+=ROR(A,27)
	orr	r9,r9,r12,lsl#24
#else
	ldr	r9,[r1],#4			@ handles unaligned
	add	r7,r8,r7,ror#2			@ E+=K_00_19
	eor	r10,r5,r6			@ F_xx_xx
	add	r7,r7,r3,ror#27			@ E+=ROR(A,27)
#ifdef __ARMEL__
	rev	r9,r9				@ byte swap
#endif
#endif
	and	r10,r4,r10,ror#2
	add	r7,r7,r9			@ E+=X[i]
	eor	r10,r10,r6,ror#2		@ F_00_19(B,C,D)
	str	r9,[r14,#-4]!
	add	r7,r7,r10			@ E+=F_00_19(B,C,D)
	ldr	r9,[r14,#15*4]
	ldr	r10,[r14,#13*4]
	ldr	r11,[r14,#7*4]
	add	r6,r8,r6,ror#2			@ E+=K_xx_xx
	ldr	r12,[r14,#2*4]
	eor	r9,r9,r10
	eor	r11,r11,r12			@ 1 cycle stall
	eor	r10,r4,r5			@ F_xx_xx
	mov	r9,r9,ror#31
	add	r6,r6,r7,ror#27			@ E+=ROR(A,27)
	eor	r9,r9,r11,ror#31
	str	r9,[r14,#-4]!
	and	r10,r3,r10,ror#2					@ F_xx_xx
						@ F_xx_xx
	add	r6,r6,r9			@ E+=X[i]
	eor	r10,r10,r5,ror#2		@ F_00_19(B,C,D)
	add	r6,r6,r10			@ E+=F_00_19(B,C,D)
	ldr	r9,[r14,#15*4]
	ldr	r10,[r14,#13*4]
	ldr	r11,[r14,#7*4]
	add	r5,r8,r5,ror#2			@ E+=K_xx_xx
	ldr	r12,[r14,#2*4]
	eor	r9,r9,r10
	eor	r11,r11,r12			@ 1 cycle stall
	eor	r10,r3,r4			@ F_xx_xx
	mov	r9,r9,ror#31
	add	r5,r5,r6,ror#27			@ E+=ROR(A,27)
	eor	r9,r9,r11,ror#31
	str	r9,[r14,#-4]!
	and	r10,r7,r10,ror#2					@ F_xx_xx
						@ F_xx_xx
	add	r5,r5,r9			@ E+=X[i]
	eor	r10,r10,r4,ror#2		@ F_00_19(B,C,D)
	add	r5,r5,r10			@ E+=F_00_19(B,C,D)
	ldr	r9,[r14,#15*4]
	ldr	r10,[r14,#13*4]
	ldr	r11,[r14,#7*4]
	add	r4,r8,r4,ror#2			@ E+=K_xx_xx
	ldr	r12,[r14,#2*4]
	eor	r9,r9,r10
	eor	r11,r11,r12			@ 1 cycle stall
	eor	r10,r7,r3			@ F_xx_xx
	mov	r9,r9,ror#31
	add	r4,r4,r5,ror#27			@ E+=ROR(A,27)
	eor	r9,r9,r11,ror#31
	str	r9,[r14,#-4]!
	and	r10,r6,r10,ror#2					@ F_xx_xx
						@ F_xx_xx
	add	r4,r4,r9			@ E+=X[i]
	eor	r10,r10,r3,ror#2		@ F_00_19(B,C,D)
	add	r4,r4,r10			@ E+=F_00_19(B,C,D)
	ldr	r9,[r14,#15*4]
	ldr	r10,[r14,#13*4]
	ldr	r11,[r14,#7*4]
	add	r3,r8,r3,ror#2			@ E+=K_xx_xx
	ldr	r12,[r14,#2*4]
	eor	r9,r9,r10
	eor	r11,r11,r12			@ 1 cycle stall
	eor	r10,r6,r7			@ F_xx_xx
	mov	r9,r9,ror#31
	add	r3,r3,r4,ror#27			@ E+=ROR(A,27)
	eor	r9,r9,r11,ror#31
	str	r9,[r14,#-4]!
	and	r10,r5,r10,ror#2					@ F_xx_xx
						@ F_xx_xx
	add	r3,r3,r9			@ E+=X[i]
	eor	r10,r10,r7,ror#2		@ F_00_19(B,C,D)
	add	r3,r3,r10			@ E+=F_00_19(B,C,D)

	ldr	r8,.LK_20_39		@ [+15+16*4]
	cmn	sp,#0			@ [+3], clear carry to denote 20_39
.L_20_39_or_60_79:
	ldr	r9,[r14,#15*4]
	ldr	r10,[r14,#13*4]
	ldr	r11,[r14,#7*4]
	add	r7,r8,r7,ror#2			@ E+=K_xx_xx
	ldr	r12,[r14,#2*4]
	eor	r9,r9,r10
	eor	r11,r11,r12			@ 1 cycle stall
	eor	r10,r5,r6			@ F_xx_xx
	mov	r9,r9,ror#31
	add	r7,r7,r3,ror#27			@ E+=ROR(A,27)
	eor	r9,r9,r11,ror#31
	str	r9,[r14,#-4]!
	eor	r10,r4,r10,ror#2					@ F_xx_xx
						@ F_xx_xx
	add	r7,r7,r9			@ E+=X[i]
	add	r7,r7,r10			@ E+=F_20_39(B,C,D)
	ldr	r9,[r14,#15*4]
	ldr	r10,[r14,#13*4]
	ldr	r11,[r14,#7*4]
	add	r6,r8,r6,ror#2			@ E+=K_xx_xx
	ldr	r12,[r14,#2*4]
	eor	r9,r9,r10
	eor	r11,r11,r12			@ 1 cycle stall
	eor	r10,r4,r5			@ F_xx_xx
	mov	r9,r9,ror#31
	add	r6,r6,r7,ror#27			@ E+=ROR(A,27)
	eor	r9,r9,r11,ror#31
	str	r9,[r14,#-4]!
	eor	r10,r3,r10,ror#2					@ F_xx_xx
						@ F_xx_xx
	add	r6,r6,r9			@ E+=X[i]
	add	r6,r6,r10			@ E+=F_20_39(B,C,D)
	ldr	r9,[r14,#15*4]
	ldr	r10,[r14,#13*4]
	ldr	r11,[r14,#7*4]
	add	r5,r8,r5,ror#2			@ E+=K_xx_xx
	ldr	r12,[r14,#2*4]
	eor	r9,r9,r10
	eor	r11,r11,r12			@ 1 cycle stall
	eor	r10,r3,r4			@ F_xx_xx
	mov	r9,r9,ror#31
	add	r5,r5,r6,ror#27			@ E+=ROR(A,27)
	eor	r9,r9,r11,ror#31
	str	r9,[r14,#-4]!
	eor	r10,r7,r10,ror#2					@ F_xx_xx
						@ F_xx_xx
	add	r5,r5,r9			@ E+=X[i]
	add	r5,r5,r10			@ E+=F_20_39(B,C,D)
	ldr	r9,[r14,#15*4]
	ldr	r10,[r14,#13*4]
	ldr	r11,[r14,#7*4]
	add	r4,r8,r4,ror#2			@ E+=K_xx_xx
	ldr	r12,[r14,#2*4]
	eor	r9,r9,r10
	eor	r11,r11,r12			@ 1 cycle stall
	eor	r10,r7,r3			@ F_xx_xx
	mov	r9,r9,ror#31
	add	r4,r4,r5,ror#27			@ E+=ROR(A,27)
	eor	r9,r9,r11,ror#31
	str	r9,[r14,#-4]!
	eor	r10,r6,r10,ror#2					@ F_xx_xx
						@ F_xx_xx
	add	r4,r4,r9			@ E+=X[i]
	add	r4,r4,r10			@ E+=F_20_39(B,C,D)
	ldr	r9,[r14,#15*4]
	ldr	r10,[r14,#13*4]
	ldr	r11,[r14,#7*4]
	add	r3,r8,r3,ror#2			@ E+=K_xx_xx
	ldr	r12,[r14,#2*4]
	eor	r9,r9,r10
	eor	r11,r11,r12			@ 1 cycle stall
	eor	r10,r6,r7			@ F_xx_xx
	mov	r9,r9,ror#31
	add	r3,r3,r4,ror#27			@ E+=ROR(A,27)
	eor	r9,r9,r11,ror#31
	str	r9,[r14,#-4]!
	eor	r10,r5,r10,ror#2					@ F_xx_xx
						@ F_xx_xx
	add	r3,r3,r9			@ E+=X[i]
	add	r3,r3,r10			@ E+=F_20_39(B,C,D)
#if defined(__thumb2__)
	mov	r12,sp
	teq	r14,r12
#else
	teq	r14,sp			@ preserve carry
#endif
	bne	.L_20_39_or_60_79	@ [+((12+3)*5+2)*4]
	bcs	.L_done			@ [+((12+3)*5+2)*4], spare 300 bytes

	ldr	r8,.LK_40_59
	sub	sp,sp,#20*4		@ [+2]
.L_40_59:
	ldr	r9,[r14,#15*4]
	ldr	r10,[r14,#13*4]
	ldr	r11,[r14,#7*4]
	add	r7,r8,r7,ror#2			@ E+=K_xx_xx
	ldr	r12,[r14,#2*4]
	eor	r9,r9,r10
	eor	r11,r11,r12			@ 1 cycle stall
	eor	r10,r5,r6			@ F_xx_xx
	mov	r9,r9,ror#31
	add	r7,r7,r3,ror#27			@ E+=ROR(A,27)
	eor	r9,r9,r11,ror#31
	str	r9,[r14,#-4]!
	and	r10,r4,r10,ror#2					@ F_xx_xx
	and	r11,r5,r6					@ F_xx_xx
	add	r7,r7,r9			@ E+=X[i]
	add	r7,r7,r10			@ E+=F_40_59(B,C,D)
	add	r7,r7,r11,ror#2
	ldr	r9,[r14,#15*4]
	ldr	r10,[r14,#13*4]
	ldr	r11,[r14,#7*4]
	add	r6,r8,r6,ror#2			@ E+=K_xx_xx
	ldr	r12,[r14,#2*4]
	eor	r9,r9,r10
	eor	r11,r11,r12			@ 1 cycle stall
	eor	r10,r4,r5			@ F_xx_xx
	mov	r9,r9,ror#31
	add	r6,r6,r7,ror#27			@ E+=ROR(A,27)
	eor	r9,r9,r11,ror#31
	str	r9,[r14,#-4]!
	and	r10,r3,r10,ror#2					@ F_xx_xx
	and	r11,r4,r5					@ F_xx_xx
	add	r6,r6,r9			@ E+=X[i]
	add	r6,r6,r10			@ E+=F_40_59(B,C,D)
	add	r6,r6,r11,ror#2
	ldr	r9,[r14,#15*4]
	ldr	r10,[r14,#13*4]
	ldr	r11,[r14,#7*4]
	add	r5,r8,r5,ror#2			@ E+=K_xx_xx
	ldr	r12,[r14,#2*4]
	eor	r9,r9,r10
	eor	r11,r11,r12			@ 1 cycle stall
	eor	r10,r3,r4			@ F_xx_xx
	mov	r9,r9,ror#31
	add	r5,r5,r6,ror#27			@ E+=ROR(A,27)
	eor	r9,r9,r11,ror#31
	str	r9,[r14,#-4]!
	and	r10,r7,r10,ror#2					@ F_xx_xx
	and	r11,r3,r4					@ F_xx_xx
	add	r5,r5,r9			@ E+=X[i]
	add	r5,r5,r10			@ E+=F_40_59(B,C,D)
	add	r5,r5,r11,ror#2
	ldr	r9,[r14,#15*4]
	ldr	r10,[r14,#13*4]
	ldr	r11,[r14,#7*4]
	add	r4,r8,r4,ror#2			@ E+=K_xx_xx
	ldr	r12,[r14,#2*4]
	eor	r9,r9,r10
	eor	r11,r11,r12			@ 1 cycle stall
	eor	r10,r7,r3			@ F_xx_xx
	mov	r9,r9,ror#31
	add	r4,r4,r5,ror#27			@ E+=ROR(A,27)
	eor	r9,r9,r11,ror#31
	str	r9,[r14,#-4]!
	and	r10,r6,r10,ror#2					@ F_xx_xx
	and	r11,r7,r3					@ F_xx_xx
	add	r4,r4,r9			@ E+=X[i]
	add	r4,r4,r10			@ E+=F_40_59(B,C,D)
	add	r4,r4,r11,ror#2
	ldr	r9,[r14,#15*4]
	ldr	r10,[r14,#13*4]
	ldr	r11,[r14,#7*4]
	add	r3,r8,r3,ror#2			@ E+=K_xx_xx
	ldr	r12,[r14,#2*4]
	eor	r9,r9,r10
	eor	r11,r11,r12			@ 1 cycle stall
	eor	r10,r6,r7			@ F_xx_xx
	mov	r9,r9,ror#31
	add	r3,r3,r4,ror#27			@ E+=ROR(A,27)
	eor	r9,r9,r11,ror#31
	str	r9,[r14,#-4]!
	and	r10,r5,r10,ror#2					@ F_xx_xx
	and	r11,r6,r7					@ F_xx_xx
	add	r3,r3,r9			@ E+=X[i]
	add	r3,r3,r10			@ E+=F_40_59(B,C,D)
	add	r3,r3,r11,ror#2
#if defined(__thumb2__)
	mov	r12,sp
	teq	r14,r12
#else
	teq	r14,sp
#endif
	bne	.L_40_59		@ [+((12+5)*5+2)*4]

	ldr	r8,.LK_60_79
	sub	sp,sp,#20*4
	cmp	sp,#0			@ set carry to denote 60_79
	b	.L_20_39_or_60_79	@ [+4], spare 300 bytes
.L_done:
	add	sp,sp,#80*4		@ "deallocate" stack frame
	ldmia	r0,{r8,r9,r10,r11,r12}
	add	r3,r8,r3
	add	r4,r9,r4
	add	r5,r10,r5,ror#2
	add	r6,r11,r6,ror#2
	add	r7,r12,r7,ror#2
	stmia	r0,{r3,r4,r5,r6,r7}
	teq	r1,r2
	bne	.Lloop			@ [+18], total 1307

#if __ARM_ARCH__>=5
	ldmia	sp!,{r4,r5,r6,r7,r8,r9,r10,r11,r12,pc}
#else
	ldmia	sp!,{r4,r5,r6,r7,r8,r9,r10,r11,r12,lr}
	tst	lr,#1
	moveq	pc,lr			@ be binary compatible with V4, yet
.word	0xe12fff1e			@ interoperable with Thumb ISA:-)
#endif
.size	sha1_block_data_order,.-sha1_block_data_order

.align	5
.LK_00_19:.word	0x5a827999
.LK_20_39:.word	0x6ed9eba1
.LK_40_59:.word	0x8f1bbcdc
.LK_60_79:.word	0xca62c1d6

.align	5
#if __ARM_MAX_ARCH__>=7
.arch	armv7-a
.fpu	neon

.globl	sha1_block_data_order_neon
.type	sha1_block_data_order_neon,%function

.align	4
sha1_block_data_order_neon:

	stmdb	sp!,{r4,r5,r6,r7,r8,r9,r10,r11,r12,lr}
	add	r2,r1,r2,lsl#6	@ r2 to point at the end of r1
	@ dmb				@ errata #451034 on early Cortex A8
	@ vstmdb	sp!,{d8-d15}	@ ABI specification says so
	mov	r14,sp
	sub	r12,sp,#64
	adr	r8,.LK_00_19
	bic	r12,r12,#15		@ align for 128-bit stores

	ldmia	r0,{r3,r4,r5,r6,r7}	@ load context
	mov	sp,r12		@ alloca

	vld1.8	{q0,q1},[r1]!	@ handles unaligned
	veor	q15,q15,q15
	vld1.8	{q2,q3},[r1]!
	vld1.32	{d28[],d29[]},[r8,:32]!	@ load K_00_19
	vrev32.8	q0,q0		@ yes, even on
	vrev32.8	q1,q1		@ big-endian...
	vrev32.8	q2,q2
	vadd.i32	q8,q0,q14
	vrev32.8	q3,q3
	vadd.i32	q9,q1,q14
	vst1.32	{q8},[r12,:128]!
	vadd.i32	q10,q2,q14
	vst1.32	{q9},[r12,:128]!
	vst1.32	{q10},[r12,:128]!
	ldr	r9,[sp]			@ big RAW stall

.Loop_neon:
	vext.8	q8,q0,q1,#8
	bic	r10,r6,r4
	add	r7,r7,r9
	and	r11,r5,r4
	vadd.i32	q13,q3,q14
	ldr	r9,[sp,#4]
	add	r7,r7,r3,ror#27
	vext.8	q12,q3,q15,#4
	eor	r11,r11,r10
	mov	r4,r4,ror#2
	add	r7,r7,r11
	veor	q8,q8,q0
	bic	r10,r5,r3
	add	r6,r6,r9
	veor	q12,q12,q2
	and	r11,r4,r3
	ldr	r9,[sp,#8]
	veor	q12,q12,q8
	add	r6,r6,r7,ror#27
	eor	r11,r11,r10
	vst1.32	{q13},[r12,:128]!
	sub	r12,r12,#64
	mov	r3,r3,ror#2
	add	r6,r6,r11
	vext.8	q13,q15,q12,#4
	bic	r10,r4,r7
	add	r5,r5,r9
	vadd.i32	q8,q12,q12
	and	r11,r3,r7
	ldr	r9,[sp,#12]
	vsri.32	q8,q12,#31
	add	r5,r5,r6,ror#27
	eor	r11,r11,r10
	mov	r7,r7,ror#2
	vshr.u32	q12,q13,#30
	add	r5,r5,r11
	bic	r10,r3,r6
	vshl.u32	q13,q13,#2
	add	r4,r4,r9
	and	r11,r7,r6
	veor	q8,q8,q12
	ldr	r9,[sp,#16]
	add	r4,r4,r5,ror#27
	veor	q8,q8,q13
	eor	r11,r11,r10
	mov	r6,r6,ror#2
	add	r4,r4,r11
	vext.8	q9,q1,q2,#8
	bic	r10,r7,r5
	add	r3,r3,r9
	and	r11,r6,r5
	vadd.i32	q13,q8,q14
	ldr	r9,[sp,#20]
	vld1.32	{d28[],d29[]},[r8,:32]!
	add	r3,r3,r4,ror#27
	vext.8	q12,q8,q15,#4
	eor	r11,r11,r10
	mov	r5,r5,ror#2
	add	r3,r3,r11
	veor	q9,q9,q1
	bic	r10,r6,r4
	add	r7,r7,r9
	veor	q12,q12,q3
	and	r11,r5,r4
	ldr	r9,[sp,#24]
	veor	q12,q12,q9
	add	r7,r7,r3,ror#27
	eor	r11,r11,r10
	vst1.32	{q13},[r12,:128]!
	mov	r4,r4,ror#2
	add	r7,r7,r11
	vext.8	q13,q15,q12,#4
	bic	r10,r5,r3
	add	r6,r6,r9
	vadd.i32	q9,q12,q12
	and	r11,r4,r3
	ldr	r9,[sp,#28]
	vsri.32	q9,q12,#31
	add	r6,r6,r7,ror#27
	eor	r11,r11,r10
	mov	r3,r3,ror#2
	vshr.u32	q12,q13,#30
	add	r6,r6,r11
	bic	r10,r4,r7
	vshl.u32	q13,q13,#2
	add	r5,r5,r9
	and	r11,r3,r7
	veor	q9,q9,q12
	ldr	r9,[sp,#32]
	add	r5,r5,r6,ror#27
	veor	q9,q9,q13
	eor	r11,r11,r10
	mov	r7,r7,ror#2
	add	r5,r5,r11
	vext.8	q10,q2,q3,#8
	bic	r10,r3,r6
	add	r4,r4,r9
	and	r11,r7,r6
	vadd.i32	q13,q9,q14
	ldr	r9,[sp,#36]
	add	r4,r4,r5,ror#27
	vext.8	q12,q9,q15,#4
	eor	r11,r11,r10
	mov	r6,r6,ror#2
	add	r4,r4,r11
	veor	q10,q10,q2
	bic	r10,r7,r5
	add	r3,r3,r9
	veor	q12,q12,q8
	and	r11,r6,r5
	ldr	r9,[sp,#40]
	veor	q12,q12,q10
	add	r3,r3,r4,ror#27
	eor	r11,r11,r10
	vst1.32	{q13},[r12,:128]!
	mov	r5,r5,ror#2
	add	r3,r3,r11
	vext.8	q13,q15,q12,#4
	bic	r10,r6,r4
	add	r7,r7,r9
	vadd.i32	q10,q12,q12
	and	r11,r5,r4
	ldr	r9,[sp,#44]
	vsri.32	q10,q12,#31
	add	r7,r7,r3,ror#27
	eor	r11,r11,r10
	mov	r4,r4,ror#2
	vshr.u32	q12,q13,#30
	add	r7,r7,r11
	bic	r10,r5,r3
	vshl.u32	q13,q13,#2
	add	r6,r6,r9
	and	r11,r4,r3
	veor	q10,q10,q12
	ldr	r9,[sp,#48]
	add	r6,r6,r7,ror#27
	veor	q10,q10,q13
	eor	r11,r11,r10
	mov	r3,r3,ror#2
	add	r6,r6,r11
	vext.8	q11,q3,q8,#8
	bic	r10,r4,r7
	add	r5,r5,r9
	and	r11,r3,r7
	vadd.i32	q13,q10,q14
	ldr	r9,[sp,#52]
	add	r5,r5,r6,ror#27
	vext.8	q12,q10,q15,#4
	eor	r11,r11,r10
	mov	r7,r7,ror#2
	add	r5,r5,r11
	veor	q11,q11,q3
	bic	r10,r3,r6
	add	r4,r4,r9
	veor	q12,q12,q9
	and	r11,r7,r6
	ldr	r9,[sp,#56]
	veor	q12,q12,q11
	add	r4,r4,r5,ror#27
	eor	r11,r11,r10
	vst1.32	{q13},[r12,:128]!
	mov	r6,r6,ror#2
	add	r4,r4,r11
	vext.8	q13,q15,q12,#4
	bic	r10,r7,r5
	add	r3,r3,r9
	vadd.i32	q11,q12,q12
	and	r11,r6,r5
	ldr	r9,[sp,#60]
	vsri.32	q11,q12,#31
	add	r3,r3,r4,ror#27
	eor	r11,r11,r10
	mov	r5,r5,ror#2
	vshr.u32	q12,q13,#30
	add	r3,r3,r11
	bic	r10,r6,r4
	vshl.u32	q13,q13,#2
	add	r7,r7,r9
	and	r11,r5,r4
	veor	q11,q11,q12
	ldr	r9,[sp,#0]
	add	r7,r7,r3,ror#27
	veor	q11,q11,q13
	eor	r11,r11,r10
	mov	r4,r4,ror#2
	add	r7,r7,r11
	vext.8	q12,q10,q11,#8
	bic	r10,r5,r3
	add	r6,r6,r9
	and	r11,r4,r3
	veor	q0,q0,q8
	ldr	r9,[sp,#4]
	add	r6,r6,r7,ror#27
	veor	q0,q0,q1
	eor	r11,r11,r10
	mov	r3,r3,ror#2
	vadd.i32	q13,q11,q14
	add	r6,r6,r11
	bic	r10,r4,r7
	veor	q12,q12,q0
	add	r5,r5,r9
	and	r11,r3,r7
	vshr.u32	q0,q12,#30
	ldr	r9,[sp,#8]
	add	r5,r5,r6,ror#27
	vst1.32	{q13},[r12,:128]!
	sub	r12,r12,#64
	eor	r11,r11,r10
	mov	r7,r7,ror#2
	vsli.32	q0,q12,#2
	add	r5,r5,r11
	bic	r10,r3,r6
	add	r4,r4,r9
	and	r11,r7,r6
	ldr	r9,[sp,#12]
	add	r4,r4,r5,ror#27
	eor	r11,r11,r10
	mov	r6,r6,ror#2
	add	r4,r4,r11
	bic	r10,r7,r5
	add	r3,r3,r9
	and	r11,r6,r5
	ldr	r9,[sp,#16]
	add	r3,r3,r4,ror#27
	eor	r11,r11,r10
	mov	r5,r5,ror#2
	add	r3,r3,r11
	vext.8	q12,q11,q0,#8
	eor	r10,r4,r6
	add	r7,r7,r9
	ldr	r9,[sp,#20]
	veor	q1,q1,q9
	eor	r11,r10,r5
	add	r7,r7,r3,ror#27
	veor	q1,q1,q2
	mov	r4,r4,ror#2
	add	r7,r7,r11
	vadd.i32	q13,q0,q14
	eor	r10,r3,r5
	add	r6,r6,r9
	veor	q12,q12,q1
	ldr	r9,[sp,#24]
	eor	r11,r10,r4
	vshr.u32	q1,q12,#30
	add	r6,r6,r7,ror#27
	mov	r3,r3,ror#2
	vst1.32	{q13},[r12,:128]!
	add	r6,r6,r11
	eor	r10,r7,r4
	vsli.32	q1,q12,#2
	add	r5,r5,r9
	ldr	r9,[sp,#28]
	eor	r11,r10,r3
	add	r5,r5,r6,ror#27
	mov	r7,r7,ror#2
	add	r5,r5,r11
	eor	r10,r6,r3
	add	r4,r4,r9
	ldr	r9,[sp,#32]
	eor	r11,r10,r7
	add	r4,r4,r5,ror#27
	mov	r6,r6,ror#2
	add	r4,r4,r11
	vext.8	q12,q0,q1,#8
	eor	r10,r5,r7
	add	r3,r3,r9
	ldr	r9,[sp,#36]
	veor	q2,q2,q10
	eor	r11,r10,r6
	add	r3,r3,r4,ror#27
	veor	q2,q2,q3
	mov	r5,r5,ror#2
	add	r3,r3,r11
	vadd.i32	q13,q1,q14
	eor	r10,r4,r6
	vld1.32	{d28[],d29[]},[r8,:32]!
	add	r7,r7,r9
	veor	q12,q12,q2
	ldr	r9,[sp,#40]
	eor	r11,r10,r5
	vshr.u32	q2,q12,#30
	add	r7,r7,r3,ror#27
	mov	r4,r4,ror#2
	vst1.32	{q13},[r12,:128]!
	add	r7,r7,r11
	eor	r10,r3,r5
	vsli.32	q2,q12,#2
	add	r6,r6,r9
	ldr	r9,[sp,#44]
	eor	r11,r10,r4
	add	r6,r6,r7,ror#27
	mov	r3,r3,ror#2
	add	r6,r6,r11
	eor	r10,r7,r4
	add	r5,r5,r9
	ldr	r9,[sp,#48]
	eor	r11,r10,r3
	add	r5,r5,r6,ror#27
	mov	r7,r7,ror#2
	add	r5,r5,r11
	vext.8	q12,q1,q2,#8
	eor	r10,r6,r3
	add	r4,r4,r9
	ldr	r9,[sp,#52]
	veor	q3,q3,q11
	eor	r11,r10,r7
	add	r4,r4,r5,ror#27
	veor	q3,q3,q8
	mov	r6,r6,ror#2
	add	r4,r4,r11
	vadd.i32	q13,q2,q14
	eor	r10,r5,r7
	add	r3,r3,r9
	veor	q12,q12,q3
	ldr	r9,[sp,#56]
	eor	r11,r10,r6
	vshr.u32	q3,q12,#30
	add	r3,r3,r4,ror#27
	mov	r5,r5,ror#2
	vst1.32	{q13},[r12,:128]!
	add	r3,r3,r11
	eor	r10,r4,r6
	vsli.32	q3,q12,#2
	add	r7,r7,r9
	ldr	r9,[sp,#60]
	eor	r11,r10,r5
	add	r7,r7,r3,ror#27
	mov	r4,r4,ror#2
	add	r7,r7,r11
	eor	r10,r3,r5
	add	r6,r6,r9
	ldr	r9,[sp,#0]
	eor	r11,r10,r4
	add	r6,r6,r7,ror#27
	mov	r3,r3,ror#2
	add	r6,r6,r11
	vext.8	q12,q2,q3,#8
	eor	r10,r7,r4
	add	r5,r5,r9
	ldr	r9,[sp,#4]
	veor	q8,q8,q0
	eor	r11,r10,r3
	add	r5,r5,r6,ror#27
	veor	q8,q8,q9
	mov	r7,r7,ror#2
	add	r5,r5,r11
	vadd.i32	q13,q3,q14
	eor	r10,r6,r3
	add	r4,r4,r9
	veor	q12,q12,q8
	ldr	r9,[sp,#8]
	eor	r11,r10,r7
	vshr.u32	q8,q12,#30
	add	r4,r4,r5,ror#27
	mov	r6,r6,ror#2
	vst1.32	{q13},[r12,:128]!
	sub	r12,r12,#64
	add	r4,r4,r11
	eor	r10,r5,r7
	vsli.32	q8,q12,#2
	add	r3,r3,r9
	ldr	r9,[sp,#12]
	eor	r11,r10,r6
	add	r3,r3,r4,ror#27
	mov	r5,r5,ror#2
	add	r3,r3,r11
	eor	r10,r4,r6
	add	r7,r7,r9
	ldr	r9,[sp,#16]
	eor	r11,r10,r5
	add	r7,r7,r3,ror#27
	mov	r4,r4,ror#2
	add	r7,r7,r11
	vext.8	q12,q3,q8,#8
	eor	r10,r3,r5
	add	r6,r6,r9
	ldr	r9,[sp,#20]
	veor	q9,q9,q1
	eor	r11,r10,r4
	add	r6,r6,r7,ror#27
	veor	q9,q9,q10
	mov	r3,r3,ror#2
	add	r6,r6,r11
	vadd.i32	q13,q8,q14
	eor	r10,r7,r4
	add	r5,r5,r9
	veor	q12,q12,q9
	ldr	r9,[sp,#24]
	eor	r11,r10,r3
	vshr.u32	q9,q12,#30
	add	r5,r5,r6,ror#27
	mov	r7,r7,ror#2
	vst1.32	{q13},[r12,:128]!
	add	r5,r5,r11
	eor	r10,r6,r3
	vsli.32	q9,q12,#2
	add	r4,r4,r9
	ldr	r9,[sp,#28]
	eor	r11,r10,r7
	add	r4,r4,r5,ror#27
	mov	r6,r6,ror#2
	add	r4,r4,r11
	eor	r10,r5,r7
	add	r3,r3,r9
	ldr	r9,[sp,#32]
	eor	r11,r10,r6
	add	r3,r3,r4,ror#27
	mov	r5,r5,ror#2
	add	r3,r3,r11
	vext.8	q12,q8,q9,#8
	add	r7,r7,r9
	and	r10,r5,r6
	ldr	r9,[sp,#36]
	veor	q10,q10,q2
	add	r7,r7,r3,ror#27
	eor	r11,r5,r6
	veor	q10,q10,q11
	add	r7,r7,r10
	and	r11,r11,r4
	vadd.i32	q13,q9,q14
	mov	r4,r4,ror#2
	add	r7,r7,r11
	veor	q12,q12,q10
	add	r6,r6,r9
	and	r10,r4,r5
	vshr.u32	q10,q12,#30
	ldr	r9,[sp,#40]
	add	r6,r6,r7,ror#27
	vst1.32	{q13},[r12,:128]!
	eor	r11,r4,r5
	add	r6,r6,r10
	vsli.32	q10,q12,#2
	and	r11,r11,r3
	mov	r3,r3,ror#2
	add	r6,r6,r11
	add	r5,r5,r9
	and	r10,r3,r4
	ldr	r9,[sp,#44]
	add	r5,r5,r6,ror#27
	eor	r11,r3,r4
	add	r5,r5,r10
	and	r11,r11,r7
	mov	r7,r7,ror#2
	add	r5,r5,r11
	add	r4,r4,r9
	and	r10,r7,r3
	ldr	r9,[sp,#48]
	add	r4,r4,r5,ror#27
	eor	r11,r7,r3
	add	r4,r4,r10
	and	r11,r11,r6
	mov	r6,r6,ror#2
	add	r4,r4,r11
	vext.8	q12,q9,q10,#8
	add	r3,r3,r9
	and	r10,r6,r7
	ldr	r9,[sp,#52]
	veor	q11,q11,q3
	add	r3,r3,r4,ror#27
	eor	r11,r6,r7
	veor	q11,q11,q0
	add	r3,r3,r10
	and	r11,r11,r5
	vadd.i32	q13,q10,q14
	mov	r5,r5,ror#2
	vld1.32	{d28[],d29[]},[r8,:32]!
	add	r3,r3,r11
	veor	q12,q12,q11
	add	r7,r7,r9
	and	r10,r5,r6
	vshr.u32	q11,q12,#30
	ldr	r9,[sp,#56]
	add	r7,r7,r3,ror#27
	vst1.32	{q13},[r12,:128]!
	eor	r11,r5,r6
	add	r7,r7,r10
	vsli.32	q11,q12,#2
	and	r11,r11,r4
	mov	r4,r4,ror#2
	add	r7,r7,r11
	add	r6,r6,r9
	and	r10,r4,r5
	ldr	r9,[sp,#60]
	add	r6,r6,r7,ror#27
	eor	r11,r4,r5
	add	r6,r6,r10
	and	r11,r11,r3
	mov	r3,r3,ror#2
	add	r6,r6,r11
	add	r5,r5,r9
	and	r10,r3,r4
	ldr	r9,[sp,#0]
	add	r5,r5,r6,ror#27
	eor	r11,r3,r4
	add	r5,r5,r10
	and	r11,r11,r7
	mov	r7,r7,ror#2
	add	r5,r5,r11
	vext.8	q12,q10,q11,#8
	add	r4,r4,r9
	and	r10,r7,r3
	ldr	r9,[sp,#4]
	veor	q0,q0,q8
	add	r4,r4,r5,ror#27
	eor	r11,r7,r3
	veor	q0,q0,q1
	add	r4,r4,r10
	and	r11,r11,r6
	vadd.i32	q13,q11,q14
	mov	r6,r6,ror#2
	add	r4,r4,r11
	veor	q12,q12,q0
	add	r3,r3,r9
	and	r10,r6,r7
	vshr.u32	q0,q12,#30
	ldr	r9,[sp,#8]
	add	r3,r3,r4,ror#27
	vst1.32	{q13},[r12,:128]!
	sub	r12,r12,#64
	eor	r11,r6,r7
	add	r3,r3,r10
	vsli.32	q0,q12,#2
	and	r11,r11,r5
	mov	r5,r5,ror#2
	add	r3,r3,r11
	add	r7,r7,r9
	and	r10,r5,r6
	ldr	r9,[sp,#12]
	add	r7,r7,r3,ror#27
	eor	r11,r5,r6
	add	r7,r7,r10
	and	r11,r11,r4
	mov	r4,r4,ror#2
	add	r7,r7,r11
	add	r6,r6,r9
	and	r10,r4,r5
	ldr	r9,[sp,#16]
	add	r6,r6,r7,ror#27
	eor	r11,r4,r5
	add	r6,r6,r10
	and	r11,r11,r3
	mov	r3,r3,ror#2
	add	r6,r6,r11
	vext.8	q12,q11,q0,#8
	add	r5,r5,r9
	and	r10,r3,r4
	ldr	r9,[sp,#20]
	veor	q1,q1,q9
	add	r5,r5,r6,ror#27
	eor	r11,r3,r4
	veor	q1,q1,q2
	add	r5,r5,r10
	and	r11,r11,r7
	vadd.i32	q13,q0,q14
	mov	r7,r7,ror#2
	add	r5,r5,r11
	veor	q12,q12,q1
	add	r4,r4,r9
	and	r10,r7,r3
	vshr.u32	q1,q12,#30
	ldr	r9,[sp,#24]
	add	r4,r4,r5,ror#27
	vst1.32	{q13},[r12,:128]!
	eor	r11,r7,r3
	add	r4,r4,r10
	vsli.32	q1,q12,#2
	and	r11,r11,r6
	mov	r6,r6,ror#2
	add	r4,r4,r11
	add	r3,r3,r9
	and	r10,r6,r7
	ldr	r9,[sp,#28]
	add	r3,r3,r4,ror#27
	eor	r11,r6,r7
	add	r3,r3,r10
	and	r11,r11,r5
	mov	r5,r5,ror#2
	add	r3,r3,r11
	add	r7,r7,r9
	and	r10,r5,r6
	ldr	r9,[sp,#32]
	add	r7,r7,r3,ror#27
	eor	r11,r5,r6
	add	r7,r7,r10
	and	r11,r11,r4
	mov	r4,r4,ror#2
	add	r7,r7,r11
	vext.8	q12,q0,q1,#8
	add	r6,r6,r9
	and	r10,r4,r5
	ldr	r9,[sp,#36]
	veor	q2,q2,q10
	add	r6,r6,r7,ror#27
	eor	r11,r4,r5
	veor	q2,q2,q3
	add	r6,r6,r10
	and	r11,r11,r3
	vadd.i32	q13,q1,q14
	mov	r3,r3,ror#2
	add	r6,r6,r11
	veor	q12,q12,q2
	add	r5,r5,r9
	and	r10,r3,r4
	vshr.u32	q2,q12,#30
	ldr	r9,[sp,#40]
	add	r5,r5,r6,ror#27
	vst1.32	{q13},[r12,:128]!
	eor	r11,r3,r4
	add	r5,r5,r10
	vsli.32	q2,q12,#2
	and	r11,r11,r7
	mov	r7,r7,ror#2
	add	r5,r5,r11
	add	r4,r4,r9
	and	r10,r7,r3
	ldr	r9,[sp,#44]
	add	r4,r4,r5,ror#27
	eor	r11,r7,r3
	add	r4,r4,r10
	and	r11,r11,r6
	mov	r6,r6,ror#2
	add	r4,r4,r11
	add	r3,r3,r9
	and	r10,r6,r7
	ldr	r9,[sp,#48]
	add	r3,r3,r4,ror#27
	eor	r11,r6,r7
	add	r3,r3,r10
	and	r11,r11,r5
	mov	r5,r5,ror#2
	add	r3,r3,r11
	vext.8	q12,q1,q2,#8
	eor	r10,r4,r6
	add	r7,r7,r9
	ldr	r9,[sp,#52]
	veor	q3,q3,q11
	eor	r11,r10,r5
	add	r7,r7,r3,ror#27
	veor	q3,q3,q8
	mov	r4,r4,ror#2
	add	r7,r7,r11
	vadd.i32	q13,q2,q14
	eor	r10,r3,r5
	add	r6,r6,r9
	veor	q12,q12,q3
	ldr	r9,[sp,#56]
	eor	r11,r10,r4
	vshr.u32	q3,q12,#30
	add	r6,r6,r7,ror#27
	mov	r3,r3,ror#2
	vst1.32	{q13},[r12,:128]!
	add	r6,r6,r11
	eor	r10,r7,r4
	vsli.32	q3,q12,#2
	add	r5,r5,r9
	ldr	r9,[sp,#60]
	eor	r11,r10,r3
	add	r5,r5,r6,ror#27
	mov	r7,r7,ror#2
	add	r5,r5,r11
	eor	r10,r6,r3
	add	r4,r4,r9
	ldr	r9,[sp,#0]
	eor	r11,r10,r7
	add	r4,r4,r5,ror#27
	mov	r6,r6,ror#2
	add	r4,r4,r11
	vadd.i32	q13,q3,q14
	eor	r10,r5,r7
	add	r3,r3,r9
	vst1.32	{q13},[r12,:128]!
	sub	r12,r12,#64
	teq	r1,r2
	sub	r8,r8,#16
	it	eq
	subeq	r1,r1,#64
	vld1.8	{q0,q1},[r1]!
	ldr	r9,[sp,#4]
	eor	r11,r10,r6
	vld1.8	{q2,q3},[r1]!
	add	r3,r3,r4,ror#27
	mov	r5,r5,ror#2
	vld1.32	{d28[],d29[]},[r8,:32]!
	add	r3,r3,r11
	eor	r10,r4,r6
	vrev32.8	q0,q0
	add	r7,r7,r9
	ldr	r9,[sp,#8]
	eor	r11,r10,r5
	add	r7,r7,r3,ror#27
	mov	r4,r4,ror#2
	add	r7,r7,r11
	eor	r10,r3,r5
	add	r6,r6,r9
	ldr	r9,[sp,#12]
	eor	r11,r10,r4
	add	r6,r6,r7,ror#27
	mov	r3,r3,ror#2
	add	r6,r6,r11
	eor	r10,r7,r4
	add	r5,r5,r9
	ldr	r9,[sp,#16]
	eor	r11,r10,r3
	add	r5,r5,r6,ror#27
	mov	r7,r7,ror#2
	add	r5,r5,r11
	vrev32.8	q1,q1
	eor	r10,r6,r3
	add	r4,r4,r9
	vadd.i32	q8,q0,q14
	ldr	r9,[sp,#20]
	eor	r11,r10,r7
	vst1.32	{q8},[r12,:128]!
	add	r4,r4,r5,ror#27
	mov	r6,r6,ror#2
	add	r4,r4,r11
	eor	r10,r5,r7
	add	r3,r3,r9
	ldr	r9,[sp,#24]
	eor	r11,r10,r6
	add	r3,r3,r4,ror#27
	mov	r5,r5,ror#2
	add	r3,r3,r11
	eor	r10,r4,r6
	add	r7,r7,r9
	ldr	r9,[sp,#28]
	eor	r11,r10,r5
	add	r7,r7,r3,ror#27
	mov	r4,r4,ror#2
	add	r7,r7,r11
	eor	r10,r3,r5
	add	r6,r6,r9
	ldr	r9,[sp,#32]
	eor	r11,r10,r4
	add	r6,r6,r7,ror#27
	mov	r3,r3,ror#2
	add	r6,r6,r11
	vrev32.8	q2,q2
	eor	r10,r7,r4
	add	r5,r5,r9
	vadd.i32	q9,q1,q14
	ldr	r9,[sp,#36]
	eor	r11,r10,r3
	vst1.32	{q9},[r12,:128]!
	add	r5,r5,r6,ror#27
	mov	r7,r7,ror#2
	add	r5,r5,r11
	eor	r10,r6,r3
	add	r4,r4,r9
	ldr	r9,[sp,#40]
	eor	r11,r10,r7
	add	r4,r4,r5,ror#27
	mov	r6,r6,ror#2
	add	r4,r4,r11
	eor	r10,r5,r7
	add	r3,r3,r9
	ldr	r9,[sp,#44]
	eor	r11,r10,r6
	add	r3,r3,r4,ror#27
	mov	r5,r5,ror#2
	add	r3,r3,r11
	eor	r10,r4,r6
	add	r7,r7,r9
	ldr	r9,[sp,#48]
	eor	r11,r10,r5
	add	r7,r7,r3,ror#27
	mov	r4,r4,ror#2
	add	r7,r7,r11
	vrev32.8	q3,q3
	eor	r10,r3,r5
	add	r6,r6,r9
	vadd.i32	q10,q2,q14
	ldr	r9,[sp,#52]
	eor	r11,r10,r4
	vst1.32	{q10},[r12,:128]!
	add	r6,r6,r7,ror#27
	mov	r3,r3,ror#2
	add	r6,r6,r11
	eor	r10,r7,r4
	add	r5,r5,r9
	ldr	r9,[sp,#56]
	eor	r11,r10,r3
	add	r5,r5,r6,ror#27
	mov	r7,r7,ror#2
	add	r5,r5,r11
	eor	r10,r6,r3
	add	r4,r4,r9
	ldr	r9,[sp,#60]
	eor	r11,r10,r7
	add	r4,r4,r5,ror#27
	mov	r6,r6,ror#2
	add	r4,r4,r11
	eor	r10,r5,r7
	add	r3,r3,r9
	eor	r11,r10,r6
	add	r3,r3,r4,ror#27
	mov	r5,r5,ror#2
	add	r3,r3,r11
	ldmia	r0,{r9,r10,r11,r12}	@ accumulate context
	add	r3,r3,r9
	ldr	r9,[r0,#16]
	add	r4,r4,r10
	add	r5,r5,r11
	add	r6,r6,r12
	it	eq
	moveq	sp,r14
	add	r7,r7,r9
	it	ne
	ldrne	r9,[sp]
	stmia	r0,{r3,r4,r5,r6,r7}
	itt	ne
	addne	r12,sp,#3*16
	bne	.Loop_neon

	@ vldmia	sp!,{d8-d15}
	ldmia	sp!,{r4,r5,r6,r7,r8,r9,r10,r11,r12,pc}
.size	sha1_block_data_order_neon,.-sha1_block_data_order_neon
#endif

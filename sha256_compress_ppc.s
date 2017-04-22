
# This file was generated using the sha2-le project from:
# https://github.com/PPC64/sha2-le

     
# Configured as:
#   STATE_MEM_16BYTE_ALIGNED = 0
#   INPUT_MEM_16BYTE_ALIGNED = 0
#   K_MEM_16BYTE_ALIGNED = 1
#   SWAP_BYTES = 0

.file "sha256_compress_ppc.s"

# Keep in mind that vector loading/store is/would-be done directly by dealing
# with 16-bytes:
# +-------+----+----+----+----+
# |       |   Vector Words:   |
# | Name  | #1 | #2 | #3 | #4 |
# +-------+----+----+----+----+
# | Va    | a  | b  | c  | d  |
# +-------+----+----+----+----+
#
# But this algorithm will mainly deal with each data (a-h) separately on a
# vector:
# +-------+----+----+----+----+
# |       |   Vector Words:   |
# | Name  | #1 | #2 | #3 | #4 |
# +-------+----+----+----+----+
# | Va    | a  | -  | -  | -  |
# | Vb    | b  | -  | -  | -  |
# | Vc    | c  | -  | -  | -  |
# | Vd    | d  | -  | -  | -  |
# +-------+----+----+----+----+

 
.text
.align 4




  
# void sha256_compress_ppc(uint32_t *STATE, const uint8_t *input, const uint32_t *k)
.globl sha256_compress_ppc
.type sha256_compress_ppc,%function
sha256_compress_ppc:

    # Saving non volatile registers
                                          
       li 0, -176; stvx 29, 1, 0
    li 0, -160; stvx 28, 1, 0
    li 0, -144; stvx 27, 1, 0
    li 0, -128; stvx 26, 1, 0
    li 0, -112; stvx 25, 1, 0
    li 0, -96; stvx 24, 1, 0
    li 0, -80; stvx 23, 1, 0
    li 0, -64; stvx 22, 1, 0
    li 0, -48; stvx 21, 1, 0
    li 0, -32; stvx 20, 1, 0
     
  # Load hash STATE to registers
  
  
    # load unaligned
    lvx    9,  0,    3
    addi   6,  3,16
    lvsr   7,  0,    6
    lvx    13,  0,    6
    vperm  9,  13,   9,  7       # a = {a,b,c,d}
    addi   6,  6,   16
    lvx    22, 0,    6
    vperm  13,  22,  13,  7       # e = {e,f,g,h}
  


  # Unpack a-h data from the packed vector to a vector register each
  
  vsldoi 10, 9, 9, 12
  vsldoi 11, 9, 9, 8
  vsldoi 12, 9, 9, 4

  
  vsldoi 14, 13, 13, 12
  vsldoi 15, 13, 13, 8
  vsldoi 16, 13, 13, 4


  # Load 16 elements from w out of the loop
  
  
    # set vrb according to alignment
    lvsr      21,  0,     4

    # unaligned load
    lvx       17,   0,     4
    addi      6,   4, 16
    lvx       18,   0,     6

    # w0 = w[j-16] to w[j-13]
    vperm     17,   18,    17,   21
    addi      6,   4, 32
    lvx       19,   0,     6

    # w1 = w[j-12] to w[j-9]
    vperm     18,   19,    18,   21
    addi      6,   4, 48
    lvx       20,   0,     6

    # w2 = w[j-8] to w[j-5]
    vperm     19,   20,    19,   21
    addi      6,   4, 64
    lvx       4,  0,     6

    # w3 = w[j-4] to w[j-1]
    vperm     20,   4,   20,   21
  

  
    # aligned load
    # vt0 = K[j-16] to K[j-13]
    lvx       4,  0,     5
    addi      6,   5,     16
    # vt1 = K[j-12] to K[j-9]
    lvx       5,  0,     6
    addi      6,   5,     32
    # vt2 = K[j-8] to K[j-5]
    lvx       6,  0,     6
    addi      6,   5,     48
    # vt3 = K[j-4] to K[j-1]
    lvx       7,  0,     6
  

  

  # Add _w to K
  vadduwm   26,4,17
  vadduwm   27,5,18
  vadduwm   28,6,19
  vadduwm   29,7,20


  
  vsldoi 23, 26, 26, 12
  vsldoi 24, 26, 26, 8
  vsldoi 25, 26, 26, 4

  # iteration: #1
  
  vsel       0,  15,  14, 13           # ch  = Ch(e,f,g)
  vxor       1, 9,  10               # intermediate Maj
  vshasigmaw 3, 13,  1,  0xF          # bse = BigSigma1(e)
  vadduwm    6, 0,  26               # vt2 = ch + kpw
  vadduwm    5, 16,  3              # vt1 = h + bse
  vsel       1, 10,  11, 1          # maj = Maj(a,b,c)
  vadduwm    7, 5, 6              # vt3 = h + bse + ch + kpw
  vshasigmaw 2, 9,  1,  0            # bsa = BigSigma0(a)
  vadduwm    8, 2, 1              # vt4 = bsa + maj
  vadduwm    12,  12,  7              # d   = d + vt3
  vadduwm    16,  7, 8              # h   = vt3 + vt4

  # iteration: #2
  
  vsel       0,  14,  13, 12           # ch  = Ch(e,f,g)
  vxor       1, 16,  9               # intermediate Maj
  vshasigmaw 3, 12,  1,  0xF          # bse = BigSigma1(e)
  vadduwm    6, 0,  23               # vt2 = ch + kpw
  vadduwm    5, 15,  3              # vt1 = h + bse
  vsel       1, 9,  10, 1          # maj = Maj(a,b,c)
  vadduwm    7, 5, 6              # vt3 = h + bse + ch + kpw
  vshasigmaw 2, 16,  1,  0            # bsa = BigSigma0(a)
  vadduwm    8, 2, 1              # vt4 = bsa + maj
  vadduwm    11,  11,  7              # d   = d + vt3
  vadduwm    15,  7, 8              # h   = vt3 + vt4

  # iteration: #3
  
  vsel       0,  13,  12, 11           # ch  = Ch(e,f,g)
  vxor       1, 15,  16               # intermediate Maj
  vshasigmaw 3, 11,  1,  0xF          # bse = BigSigma1(e)
  vadduwm    6, 0,  24               # vt2 = ch + kpw
  vadduwm    5, 14,  3              # vt1 = h + bse
  vsel       1, 16,  9, 1          # maj = Maj(a,b,c)
  vadduwm    7, 5, 6              # vt3 = h + bse + ch + kpw
  vshasigmaw 2, 15,  1,  0            # bsa = BigSigma0(a)
  vadduwm    8, 2, 1              # vt4 = bsa + maj
  vadduwm    10,  10,  7              # d   = d + vt3
  vadduwm    14,  7, 8              # h   = vt3 + vt4

  # iteration: #4
  
  vsel       0,  12,  11, 10           # ch  = Ch(e,f,g)
  vxor       1, 14,  15               # intermediate Maj
  vshasigmaw 3, 10,  1,  0xF          # bse = BigSigma1(e)
  vadduwm    6, 0,  25               # vt2 = ch + kpw
  vadduwm    5, 13,  3              # vt1 = h + bse
  vsel       1, 15,  16, 1          # maj = Maj(a,b,c)
  vadduwm    7, 5, 6              # vt3 = h + bse + ch + kpw
  vshasigmaw 2, 14,  1,  0            # bsa = BigSigma0(a)
  vadduwm    8, 2, 1              # vt4 = bsa + maj
  vadduwm    9,  9,  7              # d   = d + vt3
  vadduwm    13,  7, 8              # h   = vt3 + vt4


  
  vsldoi 23, 27, 27, 12
  vsldoi 24, 27, 27, 8
  vsldoi 25, 27, 27, 4

  # iteration: #5
  
  vsel       0,  11,  10, 9           # ch  = Ch(e,f,g)
  vxor       1, 13,  14               # intermediate Maj
  vshasigmaw 3, 9,  1,  0xF          # bse = BigSigma1(e)
  vadduwm    6, 0,  27               # vt2 = ch + kpw
  vadduwm    5, 12,  3              # vt1 = h + bse
  vsel       1, 14,  15, 1          # maj = Maj(a,b,c)
  vadduwm    7, 5, 6              # vt3 = h + bse + ch + kpw
  vshasigmaw 2, 13,  1,  0            # bsa = BigSigma0(a)
  vadduwm    8, 2, 1              # vt4 = bsa + maj
  vadduwm    16,  16,  7              # d   = d + vt3
  vadduwm    12,  7, 8              # h   = vt3 + vt4

  # iteration: #6
  
  vsel       0,  10,  9, 16           # ch  = Ch(e,f,g)
  vxor       1, 12,  13               # intermediate Maj
  vshasigmaw 3, 16,  1,  0xF          # bse = BigSigma1(e)
  vadduwm    6, 0,  23               # vt2 = ch + kpw
  vadduwm    5, 11,  3              # vt1 = h + bse
  vsel       1, 13,  14, 1          # maj = Maj(a,b,c)
  vadduwm    7, 5, 6              # vt3 = h + bse + ch + kpw
  vshasigmaw 2, 12,  1,  0            # bsa = BigSigma0(a)
  vadduwm    8, 2, 1              # vt4 = bsa + maj
  vadduwm    15,  15,  7              # d   = d + vt3
  vadduwm    11,  7, 8              # h   = vt3 + vt4

  # iteration: #7
  
  vsel       0,  9,  16, 15           # ch  = Ch(e,f,g)
  vxor       1, 11,  12               # intermediate Maj
  vshasigmaw 3, 15,  1,  0xF          # bse = BigSigma1(e)
  vadduwm    6, 0,  24               # vt2 = ch + kpw
  vadduwm    5, 10,  3              # vt1 = h + bse
  vsel       1, 12,  13, 1          # maj = Maj(a,b,c)
  vadduwm    7, 5, 6              # vt3 = h + bse + ch + kpw
  vshasigmaw 2, 11,  1,  0            # bsa = BigSigma0(a)
  vadduwm    8, 2, 1              # vt4 = bsa + maj
  vadduwm    14,  14,  7              # d   = d + vt3
  vadduwm    10,  7, 8              # h   = vt3 + vt4

  # iteration: #8
  
  vsel       0,  16,  15, 14           # ch  = Ch(e,f,g)
  vxor       1, 10,  11               # intermediate Maj
  vshasigmaw 3, 14,  1,  0xF          # bse = BigSigma1(e)
  vadduwm    6, 0,  25               # vt2 = ch + kpw
  vadduwm    5, 9,  3              # vt1 = h + bse
  vsel       1, 11,  12, 1          # maj = Maj(a,b,c)
  vadduwm    7, 5, 6              # vt3 = h + bse + ch + kpw
  vshasigmaw 2, 10,  1,  0            # bsa = BigSigma0(a)
  vadduwm    8, 2, 1              # vt4 = bsa + maj
  vadduwm    13,  13,  7              # d   = d + vt3
  vadduwm    9,  7, 8              # h   = vt3 + vt4


  
  vsldoi 23, 28, 28, 12
  vsldoi 24, 28, 28, 8
  vsldoi 25, 28, 28, 4

  # iteration: #9
  
  vsel       0,  15,  14, 13           # ch  = Ch(e,f,g)
  vxor       1, 9,  10               # intermediate Maj
  vshasigmaw 3, 13,  1,  0xF          # bse = BigSigma1(e)
  vadduwm    6, 0,  28               # vt2 = ch + kpw
  vadduwm    5, 16,  3              # vt1 = h + bse
  vsel       1, 10,  11, 1          # maj = Maj(a,b,c)
  vadduwm    7, 5, 6              # vt3 = h + bse + ch + kpw
  vshasigmaw 2, 9,  1,  0            # bsa = BigSigma0(a)
  vadduwm    8, 2, 1              # vt4 = bsa + maj
  vadduwm    12,  12,  7              # d   = d + vt3
  vadduwm    16,  7, 8              # h   = vt3 + vt4

  # iteration: #10
  
  vsel       0,  14,  13, 12           # ch  = Ch(e,f,g)
  vxor       1, 16,  9               # intermediate Maj
  vshasigmaw 3, 12,  1,  0xF          # bse = BigSigma1(e)
  vadduwm    6, 0,  23               # vt2 = ch + kpw
  vadduwm    5, 15,  3              # vt1 = h + bse
  vsel       1, 9,  10, 1          # maj = Maj(a,b,c)
  vadduwm    7, 5, 6              # vt3 = h + bse + ch + kpw
  vshasigmaw 2, 16,  1,  0            # bsa = BigSigma0(a)
  vadduwm    8, 2, 1              # vt4 = bsa + maj
  vadduwm    11,  11,  7              # d   = d + vt3
  vadduwm    15,  7, 8              # h   = vt3 + vt4

  # iteration: #11
  
  vsel       0,  13,  12, 11           # ch  = Ch(e,f,g)
  vxor       1, 15,  16               # intermediate Maj
  vshasigmaw 3, 11,  1,  0xF          # bse = BigSigma1(e)
  vadduwm    6, 0,  24               # vt2 = ch + kpw
  vadduwm    5, 14,  3              # vt1 = h + bse
  vsel       1, 16,  9, 1          # maj = Maj(a,b,c)
  vadduwm    7, 5, 6              # vt3 = h + bse + ch + kpw
  vshasigmaw 2, 15,  1,  0            # bsa = BigSigma0(a)
  vadduwm    8, 2, 1              # vt4 = bsa + maj
  vadduwm    10,  10,  7              # d   = d + vt3
  vadduwm    14,  7, 8              # h   = vt3 + vt4

  # iteration: #12
  
  vsel       0,  12,  11, 10           # ch  = Ch(e,f,g)
  vxor       1, 14,  15               # intermediate Maj
  vshasigmaw 3, 10,  1,  0xF          # bse = BigSigma1(e)
  vadduwm    6, 0,  25               # vt2 = ch + kpw
  vadduwm    5, 13,  3              # vt1 = h + bse
  vsel       1, 15,  16, 1          # maj = Maj(a,b,c)
  vadduwm    7, 5, 6              # vt3 = h + bse + ch + kpw
  vshasigmaw 2, 14,  1,  0            # bsa = BigSigma0(a)
  vadduwm    8, 2, 1              # vt4 = bsa + maj
  vadduwm    9,  9,  7              # d   = d + vt3
  vadduwm    13,  7, 8              # h   = vt3 + vt4


  
  vsldoi 23, 29, 29, 12
  vsldoi 24, 29, 29, 8
  vsldoi 25, 29, 29, 4

  # iteration: #13
  
  vsel       0,  11,  10, 9           # ch  = Ch(e,f,g)
  vxor       1, 13,  14               # intermediate Maj
  vshasigmaw 3, 9,  1,  0xF          # bse = BigSigma1(e)
  vadduwm    6, 0,  29               # vt2 = ch + kpw
  vadduwm    5, 12,  3              # vt1 = h + bse
  vsel       1, 14,  15, 1          # maj = Maj(a,b,c)
  vadduwm    7, 5, 6              # vt3 = h + bse + ch + kpw
  vshasigmaw 2, 13,  1,  0            # bsa = BigSigma0(a)
  vadduwm    8, 2, 1              # vt4 = bsa + maj
  vadduwm    16,  16,  7              # d   = d + vt3
  vadduwm    12,  7, 8              # h   = vt3 + vt4

  # iteration: #14
  
  vsel       0,  10,  9, 16           # ch  = Ch(e,f,g)
  vxor       1, 12,  13               # intermediate Maj
  vshasigmaw 3, 16,  1,  0xF          # bse = BigSigma1(e)
  vadduwm    6, 0,  23               # vt2 = ch + kpw
  vadduwm    5, 11,  3              # vt1 = h + bse
  vsel       1, 13,  14, 1          # maj = Maj(a,b,c)
  vadduwm    7, 5, 6              # vt3 = h + bse + ch + kpw
  vshasigmaw 2, 12,  1,  0            # bsa = BigSigma0(a)
  vadduwm    8, 2, 1              # vt4 = bsa + maj
  vadduwm    15,  15,  7              # d   = d + vt3
  vadduwm    11,  7, 8              # h   = vt3 + vt4

  # iteration: #15
  
  vsel       0,  9,  16, 15           # ch  = Ch(e,f,g)
  vxor       1, 11,  12               # intermediate Maj
  vshasigmaw 3, 15,  1,  0xF          # bse = BigSigma1(e)
  vadduwm    6, 0,  24               # vt2 = ch + kpw
  vadduwm    5, 10,  3              # vt1 = h + bse
  vsel       1, 12,  13, 1          # maj = Maj(a,b,c)
  vadduwm    7, 5, 6              # vt3 = h + bse + ch + kpw
  vshasigmaw 2, 11,  1,  0            # bsa = BigSigma0(a)
  vadduwm    8, 2, 1              # vt4 = bsa + maj
  vadduwm    14,  14,  7              # d   = d + vt3
  vadduwm    10,  7, 8              # h   = vt3 + vt4

  # iteration: #16
  
  vsel       0,  16,  15, 14           # ch  = Ch(e,f,g)
  vxor       1, 10,  11               # intermediate Maj
  vshasigmaw 3, 14,  1,  0xF          # bse = BigSigma1(e)
  vadduwm    6, 0,  25               # vt2 = ch + kpw
  vadduwm    5, 9,  3              # vt1 = h + bse
  vsel       1, 11,  12, 1          # maj = Maj(a,b,c)
  vadduwm    7, 5, 6              # vt3 = h + bse + ch + kpw
  vshasigmaw 2, 10,  1,  0            # bsa = BigSigma0(a)
  vadduwm    8, 2, 1              # vt4 = bsa + maj
  vadduwm    13,  13,  7              # d   = d + vt3
  vadduwm    9,  7, 8              # h   = vt3 + vt4


  # j will be multiple of 4 for loading words.
  # Whenever read, advance the pointer (e.g: when j is used in CALC_4W)
  li        8,   16*4

  # Rolling the 16 to 64 rounds
  li        6, (64-16)/8
  mtctr     6

.align 4




  
.Loop1:
  
  
    # Load aligned of K[j]
    lvx        4,  8,     5
  

  # Advance j
  addi       8,    8,     16

  # b = w[j-15], w[j-14], w[j-13], w[j-12]
  vsldoi     5,  18,    17,  12

  # c = w[j-7], w[j-6], w[j-5], w[j-4]
  vsldoi     6,  20,    19,  12

  # d = w[j-2], w[j-1], w[j-4], w[j-3]
  vsldoi     7,  20,    20,  8

  # b = s0(w[j-15]) , s0(w[j-14]) , s0(w[j-13]) , s0(w[j-12])
  vshasigmaw 5,  5,   0,   0

  # d = s1(w[j-2]) , s1(w[j-1]) , s1(w[j-4]) , s1(w[j-3])
  vshasigmaw 7,  7,   0,   0xf

  # c = s0(w[j-15]) + w[j-7],
  #     s0(w[j-14]) + w[j-6],
  #     s0(w[j-13]) + w[j-5],
  #     s0(w[j-12]) + w[j-4]
  vadduwm    6,  5,   6

  # c = s0(w[j-15]) + w[j-7] + w[j-16],
  #     s0(w[j-14]) + w[j-6] + w[j-15],
  #     s0(w[j-13]) + w[j-5] + w[j-14],
  #     s0(w[j-12]) + w[j-4] + w[j-13]
  vadduwm    6,  6,   17

  # e = s0(w[j-15]) + w[j-7] + w[j-16] + s1(w[j-2]), // w[j]
  #     s0(w[j-14]) + w[j-6] + w[j-15] + s1(w[j-1]), // w[j+1]
  #     s0(w[j-13]) + w[j-5] + w[j-14] + s1(w[j-4]), // UNDEFINED
  #     s0(w[j-12]) + w[j-4] + w[j-13] + s1(w[j-3])  // UNDEFINED
  vadduwm    8,  6,   7

  # At this point, e[0] and e[1] are the correct values to be stored at w[j]
  # and w[j+1].
  # e[2] and e[3] are not considered.
  # b = s1(w[j]) , s1(s(w[j+1]) , UNDEFINED , UNDEFINED
  vshasigmaw 5,  8,   0,   0xf

  # v5 = s1(w[j-2]) , s1(w[j-1]) , s1(w[j]) , s1(w[j+1])
  xxmrgld    39,37,39

  # c = s0(w[j-15]) + w[j-7] + w[j-16] + s1(w[j-2]), // w[j]
  #     s0(w[j-14]) + w[j-6] + w[j-15] + s1(w[j-1]), // w[j+1]
  #     s0(w[j-13]) + w[j-5] + w[j-14] + s1(w[j]),   // w[j+2]
  #     s0(w[j-12]) + w[j-4] + w[j-13] + s1(w[j+1])  // w[j+4]
  vadduwm    6,  6,   7

  # Updating w0 to w3 to hold the new previous 16 values from w.
  vmr        17,   18
  vmr        18,   19
  vmr        19,   20
  vmr        20,   6

  # Store K + w to v9 (4 values at once)
  vadduwm    22, 6,   4

  vsldoi     23, 22,  22,12
  vsldoi     24, 22,  22,8
  vsldoi     25, 22,  22,4

  # iteration: #17 #25 #33 #41 #49 #57
  
  vsel       0,  15,  14, 13           # ch  = Ch(e,f,g)
  vxor       1, 9,  10               # intermediate Maj
  vshasigmaw 3, 13,  1,  0xF          # bse = BigSigma1(e)
  vadduwm    6, 0,  22               # vt2 = ch + kpw
  vadduwm    5, 16,  3              # vt1 = h + bse
  vsel       1, 10,  11, 1          # maj = Maj(a,b,c)
  vadduwm    7, 5, 6              # vt3 = h + bse + ch + kpw
  vshasigmaw 2, 9,  1,  0            # bsa = BigSigma0(a)
  vadduwm    8, 2, 1              # vt4 = bsa + maj
  vadduwm    12,  12,  7              # d   = d + vt3
  vadduwm    16,  7, 8              # h   = vt3 + vt4

  # iteration: #18 #26 #34 #42 #50 #58
  
  vsel       0,  14,  13, 12           # ch  = Ch(e,f,g)
  vxor       1, 16,  9               # intermediate Maj
  vshasigmaw 3, 12,  1,  0xF          # bse = BigSigma1(e)
  vadduwm    6, 0,  23               # vt2 = ch + kpw
  vadduwm    5, 15,  3              # vt1 = h + bse
  vsel       1, 9,  10, 1          # maj = Maj(a,b,c)
  vadduwm    7, 5, 6              # vt3 = h + bse + ch + kpw
  vshasigmaw 2, 16,  1,  0            # bsa = BigSigma0(a)
  vadduwm    8, 2, 1              # vt4 = bsa + maj
  vadduwm    11,  11,  7              # d   = d + vt3
  vadduwm    15,  7, 8              # h   = vt3 + vt4

  # iteration: #19 #27 #35 #43 #51 #59
  
  vsel       0,  13,  12, 11           # ch  = Ch(e,f,g)
  vxor       1, 15,  16               # intermediate Maj
  vshasigmaw 3, 11,  1,  0xF          # bse = BigSigma1(e)
  vadduwm    6, 0,  24               # vt2 = ch + kpw
  vadduwm    5, 14,  3              # vt1 = h + bse
  vsel       1, 16,  9, 1          # maj = Maj(a,b,c)
  vadduwm    7, 5, 6              # vt3 = h + bse + ch + kpw
  vshasigmaw 2, 15,  1,  0            # bsa = BigSigma0(a)
  vadduwm    8, 2, 1              # vt4 = bsa + maj
  vadduwm    10,  10,  7              # d   = d + vt3
  vadduwm    14,  7, 8              # h   = vt3 + vt4

  # iteration: #20 #28 #36 #44 #52 #60
  
  vsel       0,  12,  11, 10           # ch  = Ch(e,f,g)
  vxor       1, 14,  15               # intermediate Maj
  vshasigmaw 3, 10,  1,  0xF          # bse = BigSigma1(e)
  vadduwm    6, 0,  25               # vt2 = ch + kpw
  vadduwm    5, 13,  3              # vt1 = h + bse
  vsel       1, 15,  16, 1          # maj = Maj(a,b,c)
  vadduwm    7, 5, 6              # vt3 = h + bse + ch + kpw
  vshasigmaw 2, 14,  1,  0            # bsa = BigSigma0(a)
  vadduwm    8, 2, 1              # vt4 = bsa + maj
  vadduwm    9,  9,  7              # d   = d + vt3
  vadduwm    13,  7, 8              # h   = vt3 + vt4


  
  
    # Load aligned of K[j]
    lvx        4,  8,     5
  

  # Advance j
  addi       8,    8,     16

  # b = w[j-15], w[j-14], w[j-13], w[j-12]
  vsldoi     5,  18,    17,  12

  # c = w[j-7], w[j-6], w[j-5], w[j-4]
  vsldoi     6,  20,    19,  12

  # d = w[j-2], w[j-1], w[j-4], w[j-3]
  vsldoi     7,  20,    20,  8

  # b = s0(w[j-15]) , s0(w[j-14]) , s0(w[j-13]) , s0(w[j-12])
  vshasigmaw 5,  5,   0,   0

  # d = s1(w[j-2]) , s1(w[j-1]) , s1(w[j-4]) , s1(w[j-3])
  vshasigmaw 7,  7,   0,   0xf

  # c = s0(w[j-15]) + w[j-7],
  #     s0(w[j-14]) + w[j-6],
  #     s0(w[j-13]) + w[j-5],
  #     s0(w[j-12]) + w[j-4]
  vadduwm    6,  5,   6

  # c = s0(w[j-15]) + w[j-7] + w[j-16],
  #     s0(w[j-14]) + w[j-6] + w[j-15],
  #     s0(w[j-13]) + w[j-5] + w[j-14],
  #     s0(w[j-12]) + w[j-4] + w[j-13]
  vadduwm    6,  6,   17

  # e = s0(w[j-15]) + w[j-7] + w[j-16] + s1(w[j-2]), // w[j]
  #     s0(w[j-14]) + w[j-6] + w[j-15] + s1(w[j-1]), // w[j+1]
  #     s0(w[j-13]) + w[j-5] + w[j-14] + s1(w[j-4]), // UNDEFINED
  #     s0(w[j-12]) + w[j-4] + w[j-13] + s1(w[j-3])  // UNDEFINED
  vadduwm    8,  6,   7

  # At this point, e[0] and e[1] are the correct values to be stored at w[j]
  # and w[j+1].
  # e[2] and e[3] are not considered.
  # b = s1(w[j]) , s1(s(w[j+1]) , UNDEFINED , UNDEFINED
  vshasigmaw 5,  8,   0,   0xf

  # v5 = s1(w[j-2]) , s1(w[j-1]) , s1(w[j]) , s1(w[j+1])
  xxmrgld    39,37,39

  # c = s0(w[j-15]) + w[j-7] + w[j-16] + s1(w[j-2]), // w[j]
  #     s0(w[j-14]) + w[j-6] + w[j-15] + s1(w[j-1]), // w[j+1]
  #     s0(w[j-13]) + w[j-5] + w[j-14] + s1(w[j]),   // w[j+2]
  #     s0(w[j-12]) + w[j-4] + w[j-13] + s1(w[j+1])  // w[j+4]
  vadduwm    6,  6,   7

  # Updating w0 to w3 to hold the new previous 16 values from w.
  vmr        17,   18
  vmr        18,   19
  vmr        19,   20
  vmr        20,   6

  # Store K + w to v9 (4 values at once)
  vadduwm    22, 6,   4

  vsldoi     23, 22,  22,12
  vsldoi     24, 22,  22,8
  vsldoi     25, 22,  22,4

  # iteration: #21 #29 #37 #45 #53 #61
  
  vsel       0,  11,  10, 9           # ch  = Ch(e,f,g)
  vxor       1, 13,  14               # intermediate Maj
  vshasigmaw 3, 9,  1,  0xF          # bse = BigSigma1(e)
  vadduwm    6, 0,  22               # vt2 = ch + kpw
  vadduwm    5, 12,  3              # vt1 = h + bse
  vsel       1, 14,  15, 1          # maj = Maj(a,b,c)
  vadduwm    7, 5, 6              # vt3 = h + bse + ch + kpw
  vshasigmaw 2, 13,  1,  0            # bsa = BigSigma0(a)
  vadduwm    8, 2, 1              # vt4 = bsa + maj
  vadduwm    16,  16,  7              # d   = d + vt3
  vadduwm    12,  7, 8              # h   = vt3 + vt4

  # iteration: #22 #30 #38 #46 #54 #62
  
  vsel       0,  10,  9, 16           # ch  = Ch(e,f,g)
  vxor       1, 12,  13               # intermediate Maj
  vshasigmaw 3, 16,  1,  0xF          # bse = BigSigma1(e)
  vadduwm    6, 0,  23               # vt2 = ch + kpw
  vadduwm    5, 11,  3              # vt1 = h + bse
  vsel       1, 13,  14, 1          # maj = Maj(a,b,c)
  vadduwm    7, 5, 6              # vt3 = h + bse + ch + kpw
  vshasigmaw 2, 12,  1,  0            # bsa = BigSigma0(a)
  vadduwm    8, 2, 1              # vt4 = bsa + maj
  vadduwm    15,  15,  7              # d   = d + vt3
  vadduwm    11,  7, 8              # h   = vt3 + vt4

  # iteration: #23 #31 #39 #47 #55 #63
  
  vsel       0,  9,  16, 15           # ch  = Ch(e,f,g)
  vxor       1, 11,  12               # intermediate Maj
  vshasigmaw 3, 15,  1,  0xF          # bse = BigSigma1(e)
  vadduwm    6, 0,  24               # vt2 = ch + kpw
  vadduwm    5, 10,  3              # vt1 = h + bse
  vsel       1, 12,  13, 1          # maj = Maj(a,b,c)
  vadduwm    7, 5, 6              # vt3 = h + bse + ch + kpw
  vshasigmaw 2, 11,  1,  0            # bsa = BigSigma0(a)
  vadduwm    8, 2, 1              # vt4 = bsa + maj
  vadduwm    14,  14,  7              # d   = d + vt3
  vadduwm    10,  7, 8              # h   = vt3 + vt4

  # iteration: #24 #32 #40 #48 #56 #64
  
  vsel       0,  16,  15, 14           # ch  = Ch(e,f,g)
  vxor       1, 10,  11               # intermediate Maj
  vshasigmaw 3, 14,  1,  0xF          # bse = BigSigma1(e)
  vadduwm    6, 0,  25               # vt2 = ch + kpw
  vadduwm    5, 9,  3              # vt1 = h + bse
  vsel       1, 11,  12, 1          # maj = Maj(a,b,c)
  vadduwm    7, 5, 6              # vt3 = h + bse + ch + kpw
  vshasigmaw 2, 10,  1,  0            # bsa = BigSigma0(a)
  vadduwm    8, 2, 1              # vt4 = bsa + maj
  vadduwm    13,  13,  7              # d   = d + vt3
  vadduwm    9,  7, 8              # h   = vt3 + vt4

  bdnz .Loop1

  # Update hash STATE
  
  li        6,    16
  li        7,    32

  
    lvsr      21,   0,     3
    lvx       4,   0,     3         # vt0 = STATE[0]..STATE[3]
    lvx       3,   6,    3         # vt5 = STATE[4]..STATE[8]
    vperm     4,   3,   4,   21
    lvx       2,   7,    3         # vt5 = STATE[4]..STATE[8]
    vperm     3,   2,   3,   21
  

  vmrglw    5,   10,     9             # vt1 = {a, b, ?, ?}
  vmrglw    6,   12,     11             # vt2 = {c, d, ?, ?}
  vmrglw    7,   14,     13             # vt3 = {e, f, ?, ?}
  vmrglw    8,   16,     15             # vt4 = {g, h, ?, ?}
  xxmrgld   37,38,37        # vt1 = {a, b, c, d}
  xxmrgld   39,40,39        # vt3 = {e, f, g, h}

  # vt0 = {a+STATE[0], b+STATE[1], c+STATE[2], d+STATE[3]}
  vadduwm   4,   4,   5

  # vt5 = {e+STATE[4], f+STATE[5], g+STATE[6], h+STATE[7]
  vadduwm   3,   3,   7

  
    mfvrwz    22,   4                  # aux = a+STATE[0]
    stw       22,   8(3)             # update h[3]

    # vt6 = {b+STATE[1], c+STATE[2], d+STATE[3], a+STATE[0]}
    vsldoi    2,   4,   4,   12
    mfvrwz    22,   2                  # aux = b+STATE[1]
    stw       22,   12(3)            # update h[2]

    # vt6 = {c+STATE[2], d+STATE[3], a+STATE[0], b+STATE[1]}
    vsldoi    2,   2,   2,   12
    mfvrwz    22,   2                  # aux = c+STATE[2]
    stw       22,   0(3)             # update h[1]

    # vt6 = {d+STATE[3], a+STATE[0], b+STATE[1], c+STATE[2]}
    vsldoi    2,   2,   2,   12
    mfvrwz    22,   2                  # aux = d+STATE[3]
    stw       22,   4(3)             # update h[0]
    mfvrwz    22,   3                  # aux = e+STATE[4]
    stw       22,   24(3)            # update h[7]

    # vt6 = {f+STATE[5], g+STATE[6], d+STATE[3], h+STATE[7]}
    vsldoi    2,   3,   3,   12
    mfvrwz    22,   2                  # aux = f+STATE[5]
    stw       22,   28(3)            # update h[6]

    # vt6 = {g+STATE[6], h+STATE[7], e+STATE[4], f+STATE[5]}
    vsldoi    2,   2,   2,   12
    mfvrwz    22,   2                  # aux = g+STATE[6]
    stw       22,   16(3)            # update h[5]

    # vt6 = {h+STATE[7], e+STATE[4], f+STATE[5], g+STATE[6]}
    vsldoi    2,   2,   2,   12
    mfvrwz    22,   2                  # aux = h+STATE[7]
    stw       22,   20(3)
  



    # Restoring non volatile registers
  

                                        
       li 0, -176; lvx 29, 1, 0
    li 0, -160; lvx 28, 1, 0
    li 0, -144; lvx 27, 1, 0
    li 0, -128; lvx 26, 1, 0
    li 0, -112; lvx 25, 1, 0
    li 0, -96; lvx 24, 1, 0
    li 0, -80; lvx 23, 1, 0
    li 0, -64; lvx 22, 1, 0
    li 0, -48; lvx 21, 1, 0
    li 0, -32; lvx 20, 1, 0
 
  
  blr
.size sha256_compress_ppc, . - sha256_compress_ppc


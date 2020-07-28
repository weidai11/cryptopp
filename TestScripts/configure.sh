#!/usr/bin/env bash

# Written and placed in public domain by Jeffrey Walton
#
# This script attempts to update various config_xxx.h files based on the
# current toolchain. It fills a gap where some features are enabled based on
# compiler vendor and version, but the feature is not proesent. For example,
# modern Android toolchains should be AES-NI and AVX capable, but the project
# removes the compiler support.
#
# To use the script, copy the script to the root of the Crypto++ directory.
# Set the environment, and then run the tool:
#
#     export CXX="..."
#     export CXXFLAGS="..."
#     export LDFLAGS="..."
#     ./configure.sh
#
# Use the same compiler and environment to run configure and the makefile.
#
# This script was added at Crypto++ 8.3. Please verify the earlier version of
# the library has the config_xxx.h files. The monolithic config.h was split
# into config_xxx.h in May 2019 at Crypto++ 8.3. See GH #835, PR #836.


# shellcheck disable=SC2086

TMPDIR="${TMPDIR:-/tmp}"
TOUT="${TOUT:-a.out}"

CXX="${CXX:-g++}"
CXXFLAGS="${CXXFLAGS:--DNDEBUG -g2 -O3}"
GREP="${GREP:-grep}"

# Solaris fixup
if [[ -d /usr/gnu/bin ]]; then
  GREP=/usr/gnu/bin/grep
fi

SUN_COMPILER=$(${CXX} -V 2>/dev/null | ${GREP} -i -c -E 'CC: (Sun|Studio)')
XLC_COMPILER=$(${CXX} -qversion 2>/dev/null | ${GREP} -i -c "IBM XL")

if [[ "$SUN_COMPILER" -ne 0 ]]
then
  IS_X86=$(uname -m 2>&1 | ${GREP} -c -E 'i386|i486|i585|i686')
  IS_X64=$(uname -m 2>&1 | ${GREP} -c -E 'i86pc|x86_64|amd64')
  IS_IA32=$(uname -m 2>&1 | ${GREP} -c -E 'i86pc|i386|i486|i585|i686|x86_64|amd64')
  IS_ARM32=0
  IS_ARMV8=0
  IS_PPC=0
  IS_PPC64=0
elif [[ "$XLC_COMPILER" -ne 0 ]]
then
  IS_X86=0
  IS_X64=0
  IS_IA32=0
  IS_ARM32=0
  IS_ARMV8=0
  IS_PPC=$(uname -m 2>&1 | ${GREP} -v 64 | ${GREP} -c -E 'ppc|powerpc')
  IS_PPC64=$(uname -m 2>&1 | ${GREP} -c -E 'ppc64|powerpc64')
else
  IS_X86=$(${CXX} -dumpmachine 2>&1 | ${GREP} -c -E 'i386|i486|i585|i686')
  IS_X64=$(${CXX} -dumpmachine 2>&1 | ${GREP} -c -E 'i86pc|x86_64|amd64')
  IS_IA32=$(${CXX} -dumpmachine 2>&1 | ${GREP} -c -E 'i86pc|i386|i486|i585|i686|x86_64|amd64')
  IS_ARM32=$(${CXX} -dumpmachine 2>&1 | ${GREP} -i -c -E 'arm|armhf|armv7|eabihf|armv8')
  IS_ARMV8=$(${CXX} -dumpmachine 2>&1 | ${GREP} -i -c -E 'aarch32|aarch64|arm64')
  IS_PPC=$(${CXX} -dumpmachine 2>&1 | ${GREP} -v 64 | ${GREP} -c -E 'ppc|powerpc')
  IS_PPC64=$(${CXX} -dumpmachine 2>&1 | ${GREP} -c -E 'ppc64|powerpc64')
fi

# ===========================================================================
# =============================== config_asm.h ==============================
# ===========================================================================

rm -f config_asm.h.new

# Common header
{
  echo '#ifndef CRYPTOPP_CONFIG_ASM_H'
  echo '#define CRYPTOPP_CONFIG_ASM_H'
  echo ''
  echo '// config_asm.h rewritten by configure.sh script'
  echo '//' "$(date)"
  echo ''
} >> config_asm.h.new

#############################################################################
# Intel x86-based machines

if [[ "$IS_IA32" -ne 0 ]]; then

  if [[ "${SUN_COMPILER}" -ne 0 ]]; then
    SSE2_FLAG=-xarch=sse2
    SSE3_FLAG=-xarch=sse3
    SSSE3_FLAG=-xarch=ssse3
    SSE41_FLAG=-xarch=sse4_1
    SSE42_FLAG=-xarch=sse4_2
    CLMUL_FLAG=-xarch=aes
    AESNI_FLAG=-xarch=aes
    RDRAND_FLAG=-xarch=avx_i
    RDSEED_FLAG=-xarch=avx2_i
    AVX_FLAG=-xarch=avx
    AVX2_FLAG=-xarch=avx2
    SHANI_FLAG=-xarch=sha
  else
    SSE2_FLAG=-msse2
    SSE3_FLAG=-msse3
    SSSE3_FLAG=-mssse3
    SSE41_FLAG=-msse4.1
    SSE42_FLAG=-msse4.2
    CLMUL_FLAG=-mpclmul
    AESNI_FLAG=-maes
    RDRAND_FLAG=-mrdrnd
    RDSEED_FLAG=-mrdseed
    AVX_FLAG=-mavx
    AVX2_FLAG=-mavx2
    SHANI_FLAG=-msha
  fi

  # Shell redirection
  {

  CXX_RESULT=$(${CXX} ${CXXFLAGS} ${SSE2_FLAG} TestPrograms/test_x86_sse2.cxx -o ${TOUT} 2>&1 | tr ' ' '\n' | wc -l)
  if [[ "${CXX_RESULT}" -ne 0 ]]; then
    echo '#define CRYPTOPP_DISABLE_ASM 1'
  fi

  CXX_RESULT=$(${CXX} ${CXXFLAGS} ${SSE2_FLAG} TestPrograms/test_asm_sse2.cxx -o ${TOUT} 2>&1 | tr ' ' '\n' | wc -l)
  if [[ "${CXX_RESULT}" -eq 0 ]]; then
    echo '#define CRYPTOPP_X86_ASM_AVAILABLE 1'
    if [[ "${IS_X64}" -ne 0 ]]; then
      echo '#define CRYPTOPP_X64_ASM_AVAILABLE 1'
      echo '#define CRYPTOPP_SSE2_ASM_AVAILABLE 1'
    fi
  fi

  CXX_RESULT=$(${CXX} ${CXXFLAGS} ${SSE2_FLAG} TestPrograms/test_x86_sse2.cxx -o ${TOUT} 2>&1 | tr ' ' '\n' | wc -l)
  if [[ "${CXX_RESULT}" -eq 0 ]]; then
    echo '#define CRYPTOPP_SSE2_INTRIN_AVAILABLE 1'
  fi

  CXX_RESULT=$(${CXX} ${CXXFLAGS} ${SSE3_FLAG} TestPrograms/test_x86_sse3.cxx -o ${TOUT} 2>&1 | tr ' ' '\n' | wc -l)
  if [[ "${CXX_RESULT}" -eq 0 ]]; then
    echo '#define CRYPTOPP_SSE3_AVAILABLE 1'
  else
    echo '#define CRYPTOPP_DISABLE_SSE3 1'
  fi

  CXX_RESULT=$(${CXX} ${CXXFLAGS} ${SSSE3_FLAG} TestPrograms/test_x86_ssse3.cxx -o ${TOUT} 2>&1 | tr ' ' '\n' | wc -l)
  if [[ "${CXX_RESULT}" -eq 0 ]]; then
    echo '#define CRYPTOPP_SSSE3_ASM_AVAILABLE 1'
    echo '#define CRYPTOPP_SSSE3_AVAILABLE 1'
  else
    echo '#define CRYPTOPP_DISABLE_SSSE3 1'
  fi

  CXX_RESULT=$(${CXX} ${CXXFLAGS} ${SSE41_FLAG} TestPrograms/test_x86_sse41.cxx -o ${TOUT} 2>&1 | tr ' ' '\n' | wc -l)
  if [[ "${CXX_RESULT}" -eq 0 ]]; then
    echo '#define CRYPTOPP_SSE41_AVAILABLE 1'
  else
    echo '#define CRYPTOPP_DISABLE_SSE4 1'
    echo '#define CRYPTOPP_DISABLE_SSE41 1'
  fi

  CXX_RESULT=$(${CXX} ${CXXFLAGS} ${SSE42_FLAG} TestPrograms/test_x86_sse42.cxx -o ${TOUT} 2>&1 | tr ' ' '\n' | wc -l)
  if [[ "${CXX_RESULT}" -eq 0 ]]; then
    echo '#define CRYPTOPP_SSE42_AVAILABLE 1'
  else
    echo '#define CRYPTOPP_DISABLE_SSE4 1'
    echo '#define CRYPTOPP_DISABLE_SSE42 1'
  fi

  CXX_RESULT=$(${CXX} ${CXXFLAGS} ${CLMUL_FLAG} TestPrograms/test_x86_clmul.cxx -o ${TOUT} 2>&1 | tr ' ' '\n' | wc -l)
  if [[ "${CXX_RESULT}" -eq 0 ]]; then
    echo '#define CRYPTOPP_CLMUL_AVAILABLE 1'
  else
    echo '#define CRYPTOPP_DISABLE_CLMUL 1'
  fi

  CXX_RESULT=$(${CXX} ${CXXFLAGS} ${AESNI_FLAG} TestPrograms/test_x86_aes.cxx -o ${TOUT} 2>&1 | tr ' ' '\n' | wc -l)
  if [[ "${CXX_RESULT}" -eq 0 ]]; then
    echo '#define CRYPTOPP_AESNI_AVAILABLE 1'
  else
    echo '#define CRYPTOPP_DISABLE_AESNI 1'
  fi

  CXX_RESULT=$(${CXX} ${CXXFLAGS} ${RDRAND_FLAG} TestPrograms/test_x86_rdrand.cxx -o ${TOUT} 2>&1 | tr ' ' '\n' | wc -l)
  if [[ "${CXX_RESULT}" -eq 0 ]]; then
    echo '#define CRYPTOPP_RDRAND_AVAILABLE 1'
  else
    echo '#define CRYPTOPP_DISABLE_RDRAND 1'
  fi

  CXX_RESULT=$(${CXX} ${CXXFLAGS} ${RDSEED_FLAG} TestPrograms/test_x86_rdseed.cxx -o ${TOUT} 2>&1 | tr ' ' '\n' | wc -l)
  if [[ "${CXX_RESULT}" -eq 0 ]]; then
    echo '#define CRYPTOPP_RDSEED_AVAILABLE 1'
  else
    echo '#define CRYPTOPP_DISABLE_RDSEED 1'
  fi

  CXX_RESULT=$(${CXX} ${CXXFLAGS} ${SHANI_FLAG} TestPrograms/test_x86_sha.cxx -o ${TOUT} 2>&1 | tr ' ' '\n' | wc -l)
  if [[ "${CXX_RESULT}" -eq 0 ]]; then
    echo '#define CRYPTOPP_SHANI_AVAILABLE 1'
  else
    echo '#define CRYPTOPP_DISABLE_SHANI 1'
  fi

  CXX_RESULT=$(${CXX} ${CXXFLAGS} ${AVX_FLAG} TestPrograms/test_x86_avx.cxx -o ${TOUT} 2>&1 | tr ' ' '\n' | wc -l)
  if [[ "${CXX_RESULT}" -eq 0 ]]; then
    echo '#define CRYPTOPP_AVX_AVAILABLE 1'
  else
    echo '#define CRYPTOPP_DISABLE_AVX 1'
  fi

  CXX_RESULT=$(${CXX} ${CXXFLAGS} ${AVX2_FLAG} TestPrograms/test_x86_avx2.cxx -o ${TOUT} 2>&1 | tr ' ' '\n' | wc -l)
  if [[ "${CXX_RESULT}" -eq 0 ]]; then
    echo '#define CRYPTOPP_AVX2_AVAILABLE 1'
  else
    echo '#define CRYPTOPP_DISABLE_AVX2 1'
  fi

  # No flags, requires inline ASM
  CXX_RESULT=$(${CXX} ${CXXFLAGS} TestPrograms/test_x86_via_rng.cxx -o ${TOUT} 2>&1 | tr ' ' '\n' | wc -l)
  if [[ "${CXX_RESULT}" -eq 0 ]]; then
    echo '#define CRYPTOPP_PADLOCK_RNG_AVAILABLE 1'
  else
    echo '#define CRYPTOPP_DISABLE_PADLOCK_RNG 1'
  fi

  # No flags, requires inline ASM
  CXX_RESULT=$(${CXX} ${CXXFLAGS} TestPrograms/test_x86_via_aes.cxx -o ${TOUT} 2>&1 | tr ' ' '\n' | wc -l)
  if [[ "${CXX_RESULT}" -eq 0 ]]; then
    echo '#define CRYPTOPP_PADLOCK_AES_AVAILABLE 1'
  else
    echo '#define CRYPTOPP_DISABLE_PADLOCK_AES 1'
  fi

  # No flags, requires inline ASM
  CXX_RESULT=$(${CXX} ${CXXFLAGS} TestPrograms/test_x86_via_sha.cxx -o ${TOUT} 2>&1 | tr ' ' '\n' | wc -l)
  if [[ "${CXX_RESULT}" -eq 0 ]]; then
    echo '#define CRYPTOPP_PADLOCK_SHA_AVAILABLE 1'
  else
    echo '#define CRYPTOPP_DISABLE_PADLOCK_SHA 1'
  fi

  # Clang workaround
  CXX_RESULT=$(${CXX} ${CXXFLAGS} TestPrograms/test_asm_mixed.cxx -o ${TOUT} 2>&1 | tr ' ' '\n' | wc -l)
  if [[ "${CXX_RESULT}" -ne 0 ]]; then
    echo '#define CRYPTOPP_DISABLE_MIXED_ASM 1'
  fi

  if [[ "${SUN_COMPILER}" -ne 0 ]]; then

    echo ''
    echo '// Fixup for SunCC 12.1-12.4. Bad code generation in AES_Encrypt and friends.'
    echo '#if defined(__SUNPRO_CC) && (__SUNPRO_CC <= 0x5130)'
    echo '# undef CRYPTOPP_AESNI_AVAILABLE'
    echo '#endif'
    echo ''
    echo '// Fixup for SunCC 12.1-12.6. Compiler crash on GCM_Reduce_CLMUL.'
    echo '// http://github.com/weidai11/cryptopp/issues/226'
    echo '#if defined(__SUNPRO_CC) && (__SUNPRO_CC <= 0x5150)'
    echo '# undef CRYPTOPP_CLMUL_AVAILABLE'
    echo '#endif'
  fi

  } >> config_asm.h.new

fi

#############################################################################
# ARM 32-bit machines

if [[ "$IS_ARM32" -ne 0 ]]; then

  # Shell redirection
  {

  CXX_RESULT=$(${CXX} ${CXXFLAGS} -mfpu=neon TestPrograms/test_arm_neon.cxx -o ${TOUT} 2>&1 | tr ' ' '\n' | wc -l)
  if [[ "${CXX_RESULT}" -eq 0 ]]; then
    echo '#define CRYPTOPP_ARM_NEON_HEADER 1'
  fi

  CXX_RESULT=$(${CXX} ${CXXFLAGS} -march=armv7 TestPrograms/test_cxx.cxx -o ${TOUT} 2>&1 | tr ' ' '\n' | wc -l)
  if [[ "${CXX_RESULT}" -eq 0 ]]; then
    echo '#define CRYPTOPP_ARM_ARMV7_AVAILABLE 1'
  else
    echo '#define CRYPTOPP_DISABLE_ARM_ARMV7 1'
  fi

  CXX_RESULT=$(${CXX} ${CXXFLAGS} -mfpu=neon TestPrograms/test_arm_neon.cxx -o ${TOUT} 2>&1 | tr ' ' '\n' | wc -l)
  if [[ "${CXX_RESULT}" -eq 0 ]]; then
    echo '#define CRYPTOPP_ARM_NEON_AVAILABLE 1'
  else
    echo '#define CRYPTOPP_DISABLE_ARM_NEON 1'
  fi

  # Cryptogams is special. Attempt to compile the actual source files
  CXX_RESULT=$(${CXX} ${CXXFLAGS} aes_armv4.S -o ${TOUT} 2>&1 | tr ' ' '\n' | wc -l)
  if [[ "${CXX_RESULT}" -eq 0 ]]; then
    echo '#define CRYPTOGAMS_AES_AVAILABLE 1'
  fi

  CXX_RESULT=$(${CXX} ${CXXFLAGS} sha1_armv4.S -o ${TOUT} 2>&1 | tr ' ' '\n' | wc -l)
  if [[ "${CXX_RESULT}" -eq 0 ]]; then
    echo '#define CRYPTOGAMS_SHA1_AVAILABLE 1'
  fi

  CXX_RESULT=$(${CXX} ${CXXFLAGS} sha256_armv4.S -o ${TOUT} 2>&1 | tr ' ' '\n' | wc -l)
  if [[ "${CXX_RESULT}" -eq 0 ]]; then
    echo '#define CRYPTOGAMS_SHA256_AVAILABLE 1'
  fi

  CXX_RESULT=$(${CXX} ${CXXFLAGS} sha512_armv4.S -o ${TOUT} 2>&1 | tr ' ' '\n' | wc -l)
  if [[ "${CXX_RESULT}" -eq 0 ]]; then
    echo '#define CRYPTOGAMS_SHA512_AVAILABLE 1'
  fi

  } >> config_asm.h.new

fi

#############################################################################
# ARM 64-bit machines

if [[ "$IS_ARMV8" -ne 0 ]]; then

  # Shell redirection
  {

  CXX_RESULT=$(${CXX} ${CXXFLAGS} -march=armv8-a TestPrograms/test_arm_acle.cxx -o ${TOUT} 2>&1 | tr ' ' '\n' | wc -l)
  if [[ "${CXX_RESULT}" -eq 0 ]]; then
    echo '#define CRYPTOPP_ARM_ACLE_HEADER 1'
  fi

  CXX_RESULT=$(${CXX} ${CXXFLAGS} -march=armv8-a TestPrograms/test_arm_asimd.cxx -o ${TOUT} 2>&1 | tr ' ' '\n' | wc -l)
  if [[ "${CXX_RESULT}" -eq 0 ]]; then
    echo '#define CRYPTOPP_ARM_ASIMD_AVAILABLE 1'
  else
    echo '#define CRYPTOPP_DISABLE_ARM_ASIMD 1'
  fi

  CXX_RESULT=$(${CXX} ${CXXFLAGS} -march=armv8-a+crc TestPrograms/test_arm_crc.cxx -o ${TOUT} 2>&1 | tr ' ' '\n' | wc -l)
  if [[ "${CXX_RESULT}" -eq 0 ]]; then
    echo '#define CRYPTOPP_ARM_CRC32_AVAILABLE 1'
  else
    echo '#define CRYPTOPP_DISABLE_ARM_CRC32 1'
  fi

  CXX_RESULT=$(${CXX} ${CXXFLAGS} -march=armv8-a+crypto TestPrograms/test_arm_aes.cxx -o ${TOUT} 2>&1 | tr ' ' '\n' | wc -l)
  if [[ "${CXX_RESULT}" -eq 0 ]]; then
    echo '#define CRYPTOPP_ARM_AES_AVAILABLE 1'
  else
    echo '#define CRYPTOPP_DISABLE_ARM_AES 1'
  fi

  CXX_RESULT=$(${CXX} ${CXXFLAGS} -march=armv8-a+crypto TestPrograms/test_arm_pmull.cxx -o ${TOUT} 2>&1 | tr ' ' '\n' | wc -l)
  if [[ "${CXX_RESULT}" -eq 0 ]]; then
    echo '#define CRYPTOPP_ARM_PMULL_AVAILABLE 1'
  else
    echo '#define CRYPTOPP_DISABLE_ARM_PMULL 1'
  fi

  CXX_RESULT=$(${CXX} ${CXXFLAGS} -march=armv8-a+crypto TestPrograms/test_arm_sha1.cxx -o ${TOUT} 2>&1 | tr ' ' '\n' | wc -l)
  if [[ "${CXX_RESULT}" -eq 0 ]]; then
    echo '#define CRYPTOPP_ARM_SHA_AVAILABLE 1'
    echo '#define CRYPTOPP_ARM_SHA1_AVAILABLE 1'
  else
    echo '#define CRYPTOPP_DISABLE_ARM_SHA 1'
    echo '#define CRYPTOPP_DISABLE_ARM_SHA1 1'
  fi

  CXX_RESULT=$(${CXX} ${CXXFLAGS} -march=armv8-a+crypto TestPrograms/test_arm_sha256.cxx -o ${TOUT} 2>&1 | tr ' ' '\n' | wc -l)
  if [[ "${CXX_RESULT}" -eq 0 ]]; then
    echo '#define CRYPTOPP_ARM_SHA2_AVAILABLE 1'
  else
    echo '#define CRYPTOPP_DISABLE_ARM_SHA2 1'
  fi

  CXX_RESULT=$(${CXX} ${CXXFLAGS} -march=armv8.4-a+crypto TestPrograms/test_arm_sha3.cxx -o ${TOUT} 2>&1 | tr ' ' '\n' | wc -l)
  if [[ "${CXX_RESULT}" -eq 0 ]]; then
    echo '#define CRYPTOPP_ARM_SHA3_AVAILABLE 1'
  else
    echo '#define CRYPTOPP_DISABLE_ARM_SHA3 1'
  fi

  CXX_RESULT=$(${CXX} ${CXXFLAGS} -march=armv8.4-a+crypto TestPrograms/test_arm_sha512.cxx -o ${TOUT} 2>&1 | tr ' ' '\n' | wc -l)
  if [[ "${CXX_RESULT}" -eq 0 ]]; then
    echo '#define CRYPTOPP_ARM_SHA512_AVAILABLE 1'
  else
    echo '#define CRYPTOPP_DISABLE_ARM_SHA512 1'
  fi

  CXX_RESULT=$(${CXX} ${CXXFLAGS} -march=armv8.4-a+crypto TestPrograms/test_arm_sm3.cxx -o ${TOUT} 2>&1 | tr ' ' '\n' | wc -l)
  if [[ "${CXX_RESULT}" -eq 0 ]]; then
    echo '#define CRYPTOPP_ARM_SM3_AVAILABLE 1'
  else
    echo '#define CRYPTOPP_DISABLE_ARM_SM3 1'
  fi

  CXX_RESULT=$(${CXX} ${CXXFLAGS} -march=armv8.4-a+crypto TestPrograms/test_arm_sm4.cxx -o ${TOUT} 2>&1 | tr ' ' '\n' | wc -l)
  if [[ "${CXX_RESULT}" -eq 0 ]]; then
    echo '#define CRYPTOPP_ARM_SM4_AVAILABLE 1'
  else
    echo '#define CRYPTOPP_DISABLE_ARM_SM4 1'
  fi

  } >> config_asm.h.new

fi

#############################################################################
# PowerPC machines

if [[ "$IS_PPC" -ne 0 || "$IS_PPC64" -ne 0 ]]; then

  if [[ "${XLC_COMPILER}" -ne 0 ]]; then
    POWER9_FLAG="-qarch=pwr9 -qaltivec"
    POWER8_FLAG="-qarch=pwr8 -qaltivec"
    POWER7_VSX_FLAG="-qarch=pwr7 -qvsx -qaltivec"
    POWER7_PWR_FLAG="-qarch=pwr7 -qaltivec"
    ALTIVEC_FLAG="-qaltivec"
  else
    POWER9_FLAG="-mcpu=power9"
    POWER8_FLAG="-mcpu=power8"
    POWER7_VSX_FLAG="-mcpu=power7 -mvsx"
    POWER7_PWR_FLAG="-mcpu=power7"
    ALTIVEC_FLAG="-maltivec"
  fi

  # Shell redirection
  {

  CXX_RESULT=$(${CXX} ${CXXFLAGS} ${ALTIVEC_FLAG} TestPrograms/test_ppc_altivec.cxx -o ${TOUT} 2>&1 | tr ' ' '\n' | wc -l)
  if [[ "${CXX_RESULT}" -eq 0 ]]; then
    echo '#define CRYPTOPP_ALTIVEC_AVAILABLE 1'
  else
    echo '#define CRYPTOPP_DISABLE_ALTIVEC 1'
  fi

  CXX_RESULT=$(${CXX} ${CXXFLAGS} ${POWER7_PWR_FLAG} TestPrograms/test_ppc_power7.cxx -o ${TOUT} 2>&1 | tr ' ' '\n' | wc -l)
  if [[ "${CXX_RESULT}" -eq 0 ]]; then
    echo '#define CRYPTOPP_POWER7_AVAILABLE 1'
  else
    echo '#define CRYPTOPP_DISABLE_POWER7 1'
  fi

  CXX_RESULT=$(${CXX} ${CXXFLAGS} ${POWER8_FLAG} TestPrograms/test_ppc_power8.cxx -o ${TOUT} 2>&1 | tr ' ' '\n' | wc -l)
  if [[ "${CXX_RESULT}" -eq 0 ]]; then
    echo '#define CRYPTOPP_POWER8_AVAILABLE 1'
  else
    echo '#define CRYPTOPP_DISABLE_POWER8 1'
  fi

  CXX_RESULT=$(${CXX} ${CXXFLAGS} ${POWER9_FLAG} TestPrograms/test_ppc_power9.cxx -o ${TOUT} 2>&1 | tr ' ' '\n' | wc -l)
  if [[ "${CXX_RESULT}" -ne 0 ]]; then
    echo '#define CRYPTOPP_POWER9_AVAILABLE 1'
  else
    echo '#define CRYPTOPP_DISABLE_POWER9 1'
  fi

  CXX_RESULT=$(${CXX} ${CXXFLAGS} ${POWER8_FLAG} TestPrograms/test_ppc_aes.cxx -o ${TOUT} 2>&1 | tr ' ' '\n' | wc -l)
  if [[ "${CXX_RESULT}" -eq 0 ]]; then
    echo '#define CRYPTOPP_POWER8_AES_AVAILABLE 1'
  else
    echo '#define CRYPTOPP_DISABLE_POWER8_AES 1'
  fi

  CXX_RESULT=$(${CXX} ${CXXFLAGS} ${POWER8_FLAG} TestPrograms/test_ppc_vmull.cxx -o ${TOUT} 2>&1 | tr ' ' '\n' | wc -l)
  if [[ "${CXX_RESULT}" -eq 0 ]]; then
    echo '#define CRYPTOPP_POWER8_VMULL_AVAILABLE 1'
  else
    echo '#define CRYPTOPP_DISABLE_POWER8_VMULL 1'
  fi

  CXX_RESULT=$(${CXX} ${CXXFLAGS} ${POWER8_FLAG} TestPrograms/test_ppc_sha.cxx -o ${TOUT} 2>&1 | tr ' ' '\n' | wc -l)
  if [[ "${CXX_RESULT}" -eq 0 ]]; then
    echo '#define CRYPTOPP_POWER8_SHA_AVAILABLE 1'
  else
    echo '#define CRYPTOPP_DISABLE_POWER8_SHA 1'
  fi

  } >> config_asm.h.new

fi

# Common footer
{
  echo ''
  echo '#endif'
} >> config_asm.h.new

if [[ -e config_asm.h ]]; then
  cp config_asm.h config_asm.h.old
  mv config_asm.h.new config_asm.h
fi

# ===========================================================================
# =============================== config_cxx.h ==============================
# ===========================================================================

rm -f "${TOUT}"

exit 0

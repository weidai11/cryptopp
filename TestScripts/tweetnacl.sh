#!/usr/bin/env bash

# Written and placed in public domain by Jeffrey Walton
#
# This script fetches TweetNaCl from Bernstein's site, and then
# prepares it for use in Crypto++. The script should be run from
# the Crypto++ root directory on a Unix machine because of the
# use of wget, sed, awk and friends.

wget --no-check-certificate https://tweetnacl.cr.yp.to/20140427/tweetnacl.h -O tweetnacl.h
wget --no-check-certificate https://tweetnacl.cr.yp.to/20140427/tweetnacl.c -O tweetnacl.c

########## Remove unwanted stuff ##########

echo "Removing tweetnacl.h header"
sed -e '/#include "tweetnacl.h"/d' tweetnacl.c > tweetnacl.fixed
mv tweetnacl.fixed tweetnacl.c

echo "Removing data type typedefs"
sed -e '/typedef unsigned char u8;/d' tweetnacl.c > tweetnacl.fixed
mv tweetnacl.fixed tweetnacl.c
sed -e '/typedef unsigned long u32;/d' tweetnacl.c > tweetnacl.fixed
mv tweetnacl.fixed tweetnacl.c
sed -e '/typedef unsigned long long u64;/d' tweetnacl.c > tweetnacl.fixed
mv tweetnacl.fixed tweetnacl.c
sed -e '/typedef long long i64;/d' tweetnacl.c > tweetnacl.fixed
mv tweetnacl.fixed tweetnacl.c

sed -e '/#define FOR(i,n)/d' tweetnacl.c > tweetnacl.fixed
mv tweetnacl.fixed tweetnacl.c

echo "Removing random number generator"
sed -e '/extern void randombytes/d' tweetnacl.c > tweetnacl.fixed
mv tweetnacl.fixed tweetnacl.c

########## Add wanted stuff ##########

echo "Adding headnotes"
sed -e '1i// tweetnacl.cpp - modified tweetnacl.c and placed in public domain by Jeffrey Walton' tweetnacl.c > tweetnacl.fixed
mv tweetnacl.fixed tweetnacl.c
sed -e '2i//                 tweetnacl.c written by Daniel J. Bernstein, Bernard van Gastel,' tweetnacl.c > tweetnacl.fixed
mv tweetnacl.fixed tweetnacl.c
sed -e '3i//                 Wesley Janssen, Tanja Lange, Peter Schwabe and Sjaak Smetsers' tweetnacl.c > tweetnacl.fixed
mv tweetnacl.fixed tweetnacl.c
sed -e '4i
' tweetnacl.c > tweetnacl.fixed
mv tweetnacl.fixed tweetnacl.c

echo "Adding headers"
sed -e '5i#include "pch.h"' tweetnacl.c > tweetnacl.fixed
mv tweetnacl.fixed tweetnacl.c
sed -e '6i#include "config.h"' tweetnacl.c > tweetnacl.fixed
mv tweetnacl.fixed tweetnacl.c
sed -e '7i#include "nacl.h"' tweetnacl.c > tweetnacl.fixed
mv tweetnacl.fixed tweetnacl.c
sed -e '8i#include "misc.h"' tweetnacl.c > tweetnacl.fixed
mv tweetnacl.fixed tweetnacl.c
sed -e '9i#include "osrng.h"' tweetnacl.c > tweetnacl.fixed
mv tweetnacl.fixed tweetnacl.c
sed -e '10i#include "stdcpp.h"' tweetnacl.c > tweetnacl.fixed
mv tweetnacl.fixed tweetnacl.c
sed -e '11i
' tweetnacl.c > tweetnacl.fixed
mv tweetnacl.fixed tweetnacl.c

echo "Adding opening namespace"
sed -e '13iNAMESPACE_BEGIN(CryptoPP)' tweetnacl.c > tweetnacl.fixed
mv tweetnacl.fixed tweetnacl.c
sed -e '14iNAMESPACE_BEGIN(NaCl)' tweetnacl.c > tweetnacl.fixed
mv tweetnacl.fixed tweetnacl.c

echo "Adding random number generator"
sed -e '33istatic void randombytes(uint8_t * block, uint64_t size)\
{\
    DefaultAutoSeededRNG prng;\
    prng.GenerateBlock\(block, size\);\
}\
' tweetnacl.c > tweetnacl.fixed
mv tweetnacl.fixed tweetnacl.c

########## Fix other stuff ##########

echo "Fixing data types"
sed -e 's/u8/uint8_t/g' tweetnacl.c > tweetnacl.fixed
mv tweetnacl.fixed tweetnacl.c
sed -e 's/u16/uint16_t/g' tweetnacl.c > tweetnacl.fixed
mv tweetnacl.fixed tweetnacl.c
sed -e 's/u32/uint32_t/g' tweetnacl.c > tweetnacl.fixed
mv tweetnacl.fixed tweetnacl.c
sed -e 's/u64/uint64_t/g' tweetnacl.c > tweetnacl.fixed
mv tweetnacl.fixed tweetnacl.c
sed -e 's/i64/int64_t/g' tweetnacl.c > tweetnacl.fixed
mv tweetnacl.fixed tweetnacl.c

echo "Fixing uninitalized variables"
sed -e 's/_0\[16\],$/_0\[16\] = {0},/g' tweetnacl.c > tweetnacl.fixed
mv tweetnacl.fixed tweetnacl.c
sed -e 's/gf0,$/gf0 = {0},/g' tweetnacl.c > tweetnacl.fixed
mv tweetnacl.fixed tweetnacl.c

echo "Fixing for loops"
sed -e 's/FOR(i,n)/for(i=0; i<n; ++i)/g' tweetnacl.c > tweetnacl.fixed
mv tweetnacl.fixed tweetnacl.c
sed -e 's/FOR(i,b)/for(i=0; i<b; ++i)/g' tweetnacl.c > tweetnacl.fixed
mv tweetnacl.fixed tweetnacl.c
sed -e 's/FOR(j,2)/for(j=0; j<2; ++j)/g' tweetnacl.c > tweetnacl.fixed
mv tweetnacl.fixed tweetnacl.c
sed -e 's/FOR(i,4)/for(i=0; i<4; ++i)/g' tweetnacl.c > tweetnacl.fixed
mv tweetnacl.fixed tweetnacl.c
sed -e 's/FOR(j,4)/for(j=0; j<4; ++j)/g' tweetnacl.c > tweetnacl.fixed
mv tweetnacl.fixed tweetnacl.c
sed -e 's/FOR(m,4)/for(m=0; m<4; ++m)/g' tweetnacl.c > tweetnacl.fixed
mv tweetnacl.fixed tweetnacl.c
sed -e 's/FOR(i,8)/for(i=0; i<8; ++i)/g' tweetnacl.c > tweetnacl.fixed
mv tweetnacl.fixed tweetnacl.c
sed -e 's/FOR(j,8)/for(j=0; j<8; ++j)/g' tweetnacl.c > tweetnacl.fixed
mv tweetnacl.fixed tweetnacl.c
sed -e 's/FOR(i,15)/for(i=0; i<15; ++i)/g' tweetnacl.c > tweetnacl.fixed
mv tweetnacl.fixed tweetnacl.c
sed -e 's/FOR(a,16)/for(a=0; a<16; ++a)/g' tweetnacl.c > tweetnacl.fixed
mv tweetnacl.fixed tweetnacl.c
sed -e 's/FOR(i,16)/for(i=0; i<16; ++i)/g' tweetnacl.c > tweetnacl.fixed
mv tweetnacl.fixed tweetnacl.c
sed -e 's/FOR(j,16)/for(j=0; j<16; ++j)/g' tweetnacl.c > tweetnacl.fixed
mv tweetnacl.fixed tweetnacl.c
sed -e 's/FOR(m,16)/for(m=0; m<16; ++m)/g' tweetnacl.c > tweetnacl.fixed
mv tweetnacl.fixed tweetnacl.c
sed -e 's/FOR(i,17)/for(i=0; i<17; ++i)/g' tweetnacl.c > tweetnacl.fixed
mv tweetnacl.fixed tweetnacl.c
sed -e 's/FOR(j,17)/for(j=0; j<17; ++j)/g' tweetnacl.c > tweetnacl.fixed
mv tweetnacl.fixed tweetnacl.c
sed -e 's/FOR(i,20)/for(i=0; i<20; ++i)/g' tweetnacl.c > tweetnacl.fixed
mv tweetnacl.fixed tweetnacl.c
sed -e 's/FOR(i,31)/for(i=0; i<31; ++i)/g' tweetnacl.c > tweetnacl.fixed
mv tweetnacl.fixed tweetnacl.c
sed -e 's/FOR(i,32)/for(i=0; i<32; ++i)/g' tweetnacl.c > tweetnacl.fixed
mv tweetnacl.fixed tweetnacl.c
sed -e 's/FOR(j,32)/for(j=0; j<32; ++j)/g' tweetnacl.c > tweetnacl.fixed
mv tweetnacl.fixed tweetnacl.c
sed -e 's/FOR(i,64)/for(i=0; i<64; ++i)/g' tweetnacl.c > tweetnacl.fixed
mv tweetnacl.fixed tweetnacl.c
sed -e 's/FOR(i,80)/for(i=0; i<80; ++i)/g' tweetnacl.c > tweetnacl.fixed
mv tweetnacl.fixed tweetnacl.c
sed -e 's/FOR(i,256)/for(i=0; i<256; ++i)/g' tweetnacl.c > tweetnacl.fixed
mv tweetnacl.fixed tweetnacl.c

sed -e 's/int n)/uint32_t n)/g' tweetnacl.c > tweetnacl.fixed
mv tweetnacl.fixed tweetnacl.c
sed -e 's/int64_t i,j,x\[64\];/uint64_t i; int64_t j,x\[64\];/g' tweetnacl.c > tweetnacl.fixed
mv tweetnacl.fixed tweetnacl.c

echo "Fixing initializer string"
sed -e 's/"expand 32-byte k"/{0x65,0x78,0x70,0x61,0x6E,0x64,0x20,0x33,0x32,0x2D,0x62,0x79,0x74,0x65,0x20,0x6B}/g' tweetnacl.c > tweetnacl.fixed
mv tweetnacl.fixed tweetnacl.c

echo "Improving readibility"
sed -e '/#define sv static void/d' tweetnacl.c > tweetnacl.fixed
mv tweetnacl.fixed tweetnacl.c
sed -e 's/sv/static void/g' tweetnacl.c > tweetnacl.fixed
mv tweetnacl.fixed tweetnacl.c
sed -e 's/vn/verify_n/g' tweetnacl.c > tweetnacl.fixed
mv tweetnacl.fixed tweetnacl.c

echo "Adding closing namespace"
echo "" >> tweetnacl.c
echo "NAMESPACE_END  // CryptoPP" >> tweetnacl.c
echo "NAMESPACE_END  // NaCl" >> tweetnacl.c

echo "Table of 64-bit constants"
sed -e 's/0x[0-9a-f]\{16\}ULL/W64LIT(&)/g' tweetnacl.c > tweetnacl.fixed
mv tweetnacl.fixed tweetnacl.c
sed -e 's/ULL)/)/g' tweetnacl.c > tweetnacl.fixed
mv tweetnacl.fixed tweetnacl.c

########## Cleanup ##########

echo "Renaming tweetnacl.c source file"
echo "" >> tweetnacl.c
mv tweetnacl.c tweetnacl.cpp

echo "Compiling tweetnacl.cpp source file"
g++ -Wall tweetnacl.cpp -c

unix2dos tweetnacl.h tweetnacl.c tweetnacl.cpp

# echo "Testing symbols"
# nm tweetnacl.o | grep " T " | c++filt

#!/usr/bin/env sh

IS_LINUX=$(uname -s | grep -i -c linux)
IS_SOLARIS=$(uname -s | grep -i -c sunos)
IS_DARWIN=$(uname -s | grep -i -c darwin)
IS_CYGWIN=$(uname -s | grep -i -c cygwin)
IS_OPENBSD=$(uname -s | grep -i -c openbsd)
IS_DRAGONFLY=$(uname -s | grep -i -c dragonfly)
IS_FREEBSD=$(uname -s | grep -i -c freebsd)
IS_NETBSD=$(uname -s | grep -i -c netbsd)

rm -f rdrand-x86.o rdrand-x32.o rdrand-x64.o &>/dev/null
SUCCESS=0

NASM=$(which nasm 2>&1)
if [ ! -f "$NASM" ]; then
    echo "Unable to locate Nasm"
    [ "$0" = "$BASH_SOURCE" ] && exit 1 || return 1
fi

if [ "$IS_LINUX" -eq "1" ]; then
    echo "Building rdrand and rdseed modules for Linux"
    nasm -f elf32 rdrand.s -DX86 -g -o rdrand-x86.o
    nasm -f elfx32 rdrand.s -DX32 -g -o rdrand-x32.o
    nasm -f elf64 rdrand.s -DX64 -g -o rdrand-x64.o
    SUCCESS=1
fi

if [ "$IS_OPENBSD" -eq "1" ] || [ "$IS_NETBSD" -eq "1" ] || [ "$IS_FREEBSD" -eq "1" ] || [ "$IS_DRAGONFLY" -eq "1" ]; then
    echo "Building rdrand and rdseed modules for BSD"
    nasm -f elf32 rdrand.s -DX86 -g -o rdrand-x86.o
    nasm -f elfx32 rdrand.s -DX32 -g -o rdrand-x32.o
    nasm -f elf64 rdrand.s -DX64 -g -o rdrand-x64.o
    SUCCESS=1
fi

if [ "$IS_SOLARIS" -eq "1" ]; then
    echo "Building rdrand and rdseed modules for Solaris"
    nasm -f elf32 rdrand.s -DX86 -o rdrand-x86.o
    nasm -f elfx32 rdrand.s -DX32 -o rdrand-x32.o
    nasm -f elf64 rdrand.s -DX64 -o rdrand-x64.o
    SUCCESS=1
fi

if [ "$IS_DARWIN" -eq "1" ]; then
    echo "Building rdrand and rdseed modules for Darwin"
    nasm -f macho32 rdrand.s -DDARWIN -DX86 -g -o rdrand-x86.o
    nasm -f macho64 rdrand.s -DDARWIN -DX64 -g -o rdrand-x64.o
    SUCCESS=1
fi

if [ "$IS_CYGWIN" -eq "1" ]; then
    echo "Building rdrand and rdseed modules for Cygwin"
    nasm -f win32 rdrand.s -DCYGWIN -DX86 -g -o rdrand-x86.o
    nasm -f win64 rdrand.s -DCYGWIN -DX64 -g -o rdrand-x64.o
    SUCCESS=1
fi

if [ "$SUCCESS" -eq "0" ]; then
    echo "Failed to build rdrand and rdseed modules"
    [ "$0" = "$BASH_SOURCE" ] && exit 1 || return 1
fi

[ "$0" = "$BASH_SOURCE" ] && exit 0 || return 0

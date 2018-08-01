#!/usr/bin/env bash

GREP=grep
SED=sed
AWK=awk
MAKE=make

# Fixup, Solaris and friends
if [[ (-d /usr/xpg4/bin) ]]; then
	SED=/usr/xpg4/bin/sed
	AWK=/usr/xpg4/bin/awk
	GREP=/usr/xpg4/bin/grep
elif [[ (-d /usr/bin/posix) ]]; then
	SED=/usr/bin/posix/sed
	AWK=/usr/bin/posix/awk
	GREP=/usr/bin/posix/grep
fi

# Fixup for sed and "illegal byte sequence"
IS_DARWIN=$(uname -s | "$GREP" -i -c darwin)
if [[ "$IS_DARWIN" -ne 0 ]]; then
	export LC_ALL=C
fi

# Fixup for Solaris and BSDs
if [[ ! -z $(command -v gmake) ]]; then
	MAKE=gmake
fi

# Feth the three required files
if ! wget --no-check-certificate https://raw.githubusercontent.com/noloader/cryptopp-autotools/master/Makefile.am -O Makefile.am; then
	echo "Makefile.am download failed"
	[[ "$0" = "${BASH_SOURCE[0]}" ]] && exit 1 || return 1
fi

if ! wget --no-check-certificate https://raw.githubusercontent.com/noloader/cryptopp-autotools/master/configure.ac -O configure.ac; then
	echo "configure.ac download failed"
	[[ "$0" = "${BASH_SOURCE[0]}" ]] && exit 1 || return 1
fi

if ! wget --no-check-certificate https://raw.githubusercontent.com/noloader/cryptopp-autotools/master/libcryptopp.pc.in -O libcryptopp.pc.in; then
	echo "libcryptopp.pc.in download failed"
	[[ "$0" = "${BASH_SOURCE[0]}" ]] && exit 1 || return 1
fi

# Run autoreconf twice on failure. Also see
# https://github.com/tracebox/tracebox/issues/57

mkdir -p m4/

if [[ -z $(command -v autoupdate) ]]; then
	echo "Cannot find autoupdate. Things may fail."
fi

if [[ -z $(command -v libtoolize) ]]; then
	echo "Cannot find libtoolize. Things may fail."
fi

if [[ -z $(command -v autoreconf) ]]; then
	echo "Cannot find autoreconf. Things may fail."
fi

if ! autoupdate; then
	echo "autoupdate failed."
	[[ "$0" = "${BASH_SOURCE[0]}" ]] && exit 1 || return 1
fi

if ! autoreconf -fi; then
	echo "autoreconf failed, running libtoolize."
	if ! libtoolize -fi; then
		echo "libtoolize failed."
		[[ "$0" = "${BASH_SOURCE[0]}" ]] && exit 1 || return 1
	fi
	if ! autoreconf -vfi; then
		echo "autoreconf failed, again."
		[[ "$0" = "${BASH_SOURCE[0]}" ]] && exit 1 || return 1
	fi
fi

if ! ./configure; then
	echo "configure failed."
	[[ "$0" = "${BASH_SOURCE[0]}" ]] && exit 1 || return 1
fi

make clean 2>/dev/null

if ! "$MAKE" -j2 -f Makefile; then
	echo "make failed."
	[[ "$0" = "${BASH_SOURCE[0]}" ]] && exit 1 || return 1
fi

if ! ./cryptestcwd v; then
	echo "cryptestcwd v failed."
	[[ "$0" = "${BASH_SOURCE[0]}" ]] && exit 1 || return 1
fi

if ! ./cryptestcwd tv all; then
	echo "cryptestcwd tv all failed."
	[[ "$0" = "${BASH_SOURCE[0]}" ]] && exit 1 || return 1
fi

# Return success
[[ "$0" = "${BASH_SOURCE[0]}" ]] && exit 0 || return 0

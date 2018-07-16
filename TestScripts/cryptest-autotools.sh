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

# Convert as necessary
if [[ ! -z $(command -v dos2unix) ]]; then
	dos2unix Makefile.am configure.ac libcryptopp.pc.in
fi

# Trim trailing whitespace
if [[ ! -z $(command -v "$SED") ]]; then
	"$SED" -e's/[[:space:]]*$//' Makefile.am > Makefile.am.fixed
	"$SED" -e's/[[:space:]]*$//' configure.ac > configure.ac.fixed
	"$SED" -e's/[[:space:]]*$//' libcryptopp.pc.in > libcryptopp.pc.in.fixed
	mv Makefile.am.fixed Makefile.am
	mv configure.ac.fixed configure.ac
	mv libcryptopp.pc.in.fixed libcryptopp.pc.in
fi

mkdir -p m4/
if ! autoreconf --force --install --warnings=all; then
	echo "autoreconf failed"
	[[ "$0" = "${BASH_SOURCE[0]}" ]] && exit 1 || return 1
fi

if ! ./configure; then
	echo "configure failed"
	[[ "$0" = "${BASH_SOURCE[0]}" ]] && exit 1 || return 1
fi

if ! "$MAKE" -j2 -f Makefile; then
	echo "make failed"
	[[ "$0" = "${BASH_SOURCE[0]}" ]] && exit 1 || return 1
fi

if ! ./cryptestcwd v; then
	echo "cryptestcwd v failed"
	[[ "$0" = "${BASH_SOURCE[0]}" ]] && exit 1 || return 1
fi

if ! ./cryptestcwd tv all; then
	echo "cryptestcwd v failed"
	[[ "$0" = "${BASH_SOURCE[0]}" ]] && exit 1 || return 1
fi

# Return success
[[ "$0" = "${BASH_SOURCE[0]}" ]] && exit 0 || return 0

#!/usr/bin/env bash

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
if [[ ! -z $(command -v sed) ]]; then
	sed -e's/[[:space:]]*$//' Makefile.am > Makefile.am.fixed
	sed -e's/[[:space:]]*$//' configure.ac > configure.ac.fixed
	sed -e's/[[:space:]]*$//' libcryptopp.pc.in > libcryptopp.pc.in.fixed
	mv Makefile.am.fixed Makefile.am
	mv configure.ac.fixed configure.ac
	mv libcryptopp.pc.in.fixed libcryptopp.pc.in
fi

if ! autoreconf --force --install --warnings=all; then
	echo "autoreconf failed"
	[[ "$0" = "${BASH_SOURCE[0]}" ]] && exit 1 || return 1
fi

if ! ./configure; then
	echo "configure failed"
	[[ "$0" = "${BASH_SOURCE[0]}" ]] && exit 1 || return 1
fi

if ! make -j2 -f Makefile; then
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



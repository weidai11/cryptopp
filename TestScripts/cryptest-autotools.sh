#!/usr/bin/env bash

PWD_DIR=$(pwd)
function cleanup {
	cd "$PWD_DIR"
}
trap cleanup EXIT

#############################################################################

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
else
	MAKE=make
fi

# Fixup for missing libtool
if [[ ! -z $(command -v libtoolize) ]]; then
	LIBTOOLIZE=$(command -v libtoolize)
elif [[ ! -z $(command -v glibtoolize) ]]; then
	LIBTOOLIZE=$(command -v glibtoolize)
elif [[ ! -z $(command -v libtool) ]]; then
	LIBTOOLIZE=$(command -v libtool)
elif [[ ! -z $(command -v glibtool) ]]; then
	LIBTOOLIZE=$(command -v glibtool)
fi

#############################################################################

echo "Downloading configure.ac"
if ! wget -O configure.ac -q --no-check-certificate 'https://raw.githubusercontent.com/noloader/cryptopp-autotools/master/configure.ac'; then
	echo "configure.ac download failed"
	[[ "$0" = "${BASH_SOURCE[0]}" ]] && exit 1 || return 1
fi

echo "Downloading Makefile.am"
if ! wget -O Makefile.am -q --no-check-certificate 'https://raw.githubusercontent.com/noloader/cryptopp-autotools/master/Makefile.am'; then
	echo "Makefile.am download failed"
	[[ "$0" = "${BASH_SOURCE[0]}" ]] && exit 1 || return 1
fi

echo "Downloading libcryptopp.pc.in"
if ! wget -O libcryptopp.pc.in -q --no-check-certificate 'https://raw.githubusercontent.com/noloader/cryptopp-autotools/master/libcryptopp.pc.in'; then
	echo "libcryptopp.pc.in download failed"
	[[ "$0" = "${BASH_SOURCE[0]}" ]] && exit 1 || return 1
fi

mkdir -p m4/

#############################################################################

if [[ -z $(command -v autoupdate) ]]; then
	echo "Cannot find autoupdate. Things may fail."
fi

if [[ -z "$LIBTOOLIZE" ]]; then
	echo "Cannot find libtoolize. Things may fail."
fi

if [[ -z $(command -v automake) ]]; then
	echo "Cannot find automake. Things may fail."
fi

if [[ -z $(command -v autoreconf) ]]; then
	echo "Cannot find autoreconf. Things may fail."
fi

echo "Running autoupdate"
if ! autoupdate &>/dev/null; then
	echo "autoupdate failed."
	[[ "$0" = "${BASH_SOURCE[0]}" ]] && exit 1 || return 1
fi

echo "Running libtoolize"
if ! "$LIBTOOLIZE" --force --install &>/dev/null; then
	echo "libtoolize failed... skipping."
	# [[ "$0" = "${BASH_SOURCE[0]}" ]] && exit 1 || return 1
fi

# Run autoreconf twice on failure. Also see
# https://github.com/tracebox/tracebox/issues/57
echo "Running autoreconf"
if ! autoreconf --force --install &>/dev/null; then
	echo "autoreconf failed, running again."
	if ! autoreconf --force --install; then
		echo "autoreconf failed, again."
		[[ "$0" = "${BASH_SOURCE[0]}" ]] && exit 1 || return 1
	fi
fi

#############################################################################

# Update config.sub config.guess. GNU recommends using the latest for all projects.
echo "Updating config.sub"
wget -O config.sub.new -q --no-check-certificate 'https://git.savannah.gnu.org/gitweb/?p=config.git;a=blob_plain;f=config.sub'

# Solaris removes +w, can't overwrite
chmod +w config.sub
mv config.sub.new config.sub
chmod +x config.sub

if [[ "$IS_DARWIN" -ne 0 ]] && [[ -n $(command -v xattr) ]]; then
	echo "Removing config.sub quarantine"
	xattr -d "com.apple.quarantine" config.sub &>/dev/null
fi

echo "Updating config.guess"
wget -O config.guess.new -q --no-check-certificate 'https://git.savannah.gnu.org/gitweb/?p=config.git;a=blob_plain;f=config.guess'

# Solaris removes +w, can't overwrite
chmod +w config.guess
mv config.guess.new config.guess
chmod +x config.guess

if [[ "$IS_DARWIN" -ne 0 ]] && [[ -n $(command -v xattr) ]]; then
	echo "Removing config.guess quarantine"
	xattr -d "com.apple.quarantine" config.guess &>/dev/null
fi

#############################################################################

echo "Running configure"
echo ""

if ! ./configure; then
	echo "configure failed."
	[[ "$0" = "${BASH_SOURCE[0]}" ]] && exit 1 || return 1
fi

"$MAKE" clean 2>/dev/null

#############################################################################

if ! "$MAKE" -j2 -f Makefile; then
	echo "make failed."
	[[ "$0" = "${BASH_SOURCE[0]}" ]] && exit 1 || return 1
fi

if ! ./cryptest v; then
	echo "cryptest v failed."
	[[ "$0" = "${BASH_SOURCE[0]}" ]] && exit 1 || return 1
fi

if ! ./cryptest tv all; then
	echo "cryptest tv all failed."
	[[ "$0" = "${BASH_SOURCE[0]}" ]] && exit 1 || return 1
fi

# Return success
[[ "$0" = "${BASH_SOURCE[0]}" ]] && exit 0 || return 0

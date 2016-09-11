#!/usr/bin/env bash

# ====================================================================
# Tests iOS cross-compiles
#
# Crypto++ Library is copyrighted as a compilation and (as of version 5.6.2)
# licensed under the Boost Software License 1.0, while the individual files
# in the compilation are all public domain.
#
# See http://www.cryptopp.com/wiki/iOS_(Command_Line) for more details
# ====================================================================

PLATFORMS=(iPhoneOS iPhoneSimulator WatchOS WatchSimulator AppleTVOS AppleTVSimulator)
for platform in ${PLATFORMS[@]}
do
	make -f GNUmakefile-cross distclean > /dev/null 2>&1

	MESSAGE="Testing for Xcode support of $platform"
	LEN=${#MESSAGE}
	HEADER=$(seq  -f "*" -s '' $LEN)

	echo
	echo "$HEADER"
	echo "$MESSAGE"

	# Test if we can set the environment for the platform
	./setenv-ios.sh "$platform" > /dev/null 2>&1

	if [ "$?" -eq "0" ]; then
		echo
		echo "Building for $platform..."
		echo

		. ./setenv-ios.sh "$platform"
		make -f GNUmakefile-cross static dynamic cryptest.exe
	else
		echo
		echo "$platform not supported by Xcode"
	fi
done

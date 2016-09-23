#!/usr/bin/env bash

# ====================================================================
# Tests Android cross-compiles
#
# Crypto++ Library is copyrighted as a compilation and (as of version 5.6.2)
# licensed under the Boost Software License 1.0, while the individual files
# in the compilation are all public domain.
#
# See http://www.cryptopp.com/wiki/Android_(Command_Line) for more details
# ====================================================================

PLATFORMS=(armeabi armeabi-v7a armeabi-v7a-hard armv7a-neon aarch64 mipsel x86 x86_64)
RUNTIMES=(stlport-static stlport-shared gabi++-static gabi++-shared)
for platform in ${PLATFORMS[@]}
do
	for runtime in ${RUNTIMES[@]}
	do
		make -f GNUmakefile-cross distclean > /dev/null 2>&1

		MESSAGE="Testing for Android support of $platform using $runtime"
		LEN=${#MESSAGE}
		HEADER=$(seq  -f "*" -s '' $LEN)

		echo
		echo "$HEADER"
		echo "$MESSAGE"

		# Test if we can set the environment for the platform
		./setenv-android.sh "$platform" "$runtime" > /dev/null 2>&1

		if [ "$?" -eq "0" ]; then
			echo
			echo "Building for $platform using $runtime..."
			echo

			. ./setenv-android.sh "$platform" "$runtime"
			make -f GNUmakefile-cross static dynamic cryptest.exe
		else
			echo
			echo "$platform not supported by Android"
		fi
	done
done

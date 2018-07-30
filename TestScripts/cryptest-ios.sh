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

if [ -z $(command -v ./setenv-ios.sh) ]; then
	echo "Failed to locate setenv-ios.sh"
	ls -Al *.sh
	[[ "$0" = "${BASH_SOURCE[0]}" ]] && exit 1 || return 1
fi

if [ -z "${PLATFORM-}" ]; then
	PLATFORMS=(iPhoneOS iPhoneSimulator Arm64 WatchOS WatchSimulator AppleTVOS AppleTVSimulator)
else
	PLATFORMS=(${PLATFORM})
fi

for platform in ${PLATFORMS[@]}
do
	make -f GNUmakefile-cross distclean > /dev/null 2>&1

	echo
	echo "====================================================="
	echo "Testing for iOS support of $platform"

	# Test if we can set the environment for the platform
	./setenv-ios.sh "$platform"

	if [ "$?" -ne "0" ];
	then
		echo
		echo "$platform not supported by Xcode"
		echo "$platform ==> FAILURE" >> /tmp/build.log

		touch /tmp/build.failed
		continue
	fi

	echo
	echo "Building for $platform using $runtime..."
	echo

	# run in subshell to not keep any env vars
	(
		source ./setenv-ios.sh "$platform" > /dev/null 2>&1
		make -f GNUmakefile-cross static dynamic cryptest.exe
		if [ "$?" -eq "0" ]; then
			echo "$platform ==> SUCCESS" >> /tmp/build.log
		else
			echo "$platform ==> FAILURE" >> /tmp/build.log
			touch /tmp/build.failed
		fi
	)
done

cat /tmp/build.log

# let the script fail if any of the builds failed
if [ -f /tmp/build.failed ]; then
	[[ "$0" = "${BASH_SOURCE[0]}" ]] && exit 1 || return 1
fi

[[ "$0" = "${BASH_SOURCE[0]}" ]] && exit 0 || return 0

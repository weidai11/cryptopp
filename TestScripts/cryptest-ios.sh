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

if [ -z "${PLATFORM-}" ]; then
	PLATFORMS=(iPhoneOS iPhoneSimulator WatchOS WatchSimulator AppleTVOS AppleTVSimulator)
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

	if [ "$?" -eq "0" ]; then
		echo
		echo "Building for $platform using $runtime..."
		echo

		# run in subshell to not keep any env vars
		(
			. ./setenv-ios.sh "$platform" > /dev/null 2>&1
			make -f GNUmakefile-cross static dynamic cryptest.exe
			if [ "$?" -eq "0" ]; then
				echo "$platform ==> SUCCESS" >> /tmp/build.log
			else
				echo "$platform ==> FAILURE" >> /tmp/build.log
				touch /tmp/build.failed
			fi
		)
	else
		echo
		echo "$platform not supported by Xcode"
		echo "$platform ==> FAILURE" >> /tmp/build.log
		touch /tmp/build.failed
	fi
done

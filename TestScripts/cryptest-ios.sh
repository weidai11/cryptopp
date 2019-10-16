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

if [ -z "$(command -v ./setenv-ios.sh)" ]; then
	echo "Failed to locate setenv-ios.sh"
	[[ "$0" = "${BASH_SOURCE[0]}" ]] && exit 1 || return 1
fi

# Temp directory
if [[ -z "$TMPDIR" ]]; then
	TMPDIR="$HOME/tmp"
	mkdir "$TMPDIR"
fi

MAKE_JOBS=2

# Cleanup old artifacts
rm -rf "$TMPDIR/build.failed" 2>/dev/null
rm -rf "$TMPDIR/build.log" 2>/dev/null

if [ "$#" -gt 0 ]; then
	# Accept platforms on the command line
	PLATFORMS=("$@")
elif [ -n "$PLATFORM" ]; then
	# Accept platforms in the environment
	PLATFORMS=("$PLATFORM")
else
	# Use all platforms
	PLATFORMS=(iPhoneOS iPhoneSimulator Arm64 WatchOS WatchSimulator AppleTVOS AppleTVSimulator)
fi

for platform in "${PLATFORMS[@]}"
do
	make -f GNUmakefile-cross distclean > /dev/null 2>&1

	echo
	echo "====================================================="
	echo "Testing for iOS support of $platform"

	# Test if we can set the environment for the platform
	if ! ./setenv-ios.sh "$platform";
	then
		echo
		echo "$platform not supported by Xcode"
		echo "$platform ==> FAILURE" >> "$TMPDIR/build.log"

		touch "$TMPDIR/build.failed"
		continue
	fi

	echo
	echo "Building for $platform..."
	echo

	# run in subshell to not keep any envars
	(
		source ./setenv-ios.sh "$platform" > /dev/null 2>&1
		if make -k -j "$MAKE_JOBS" -f GNUmakefile-cross static dynamic cryptest.exe;
		then
			echo "$platform ==> SUCCESS" >> "$TMPDIR/build.log"
		else
			echo "$platform ==> FAILURE" >> "$TMPDIR/build.log"
			touch "$TMPDIR/build.failed"
		fi
	)
done

cat "$TMPDIR/build.log"

# let the script fail if any of the builds failed
if [ -f "$TMPDIR/build.failed" ]; then
	[[ "$0" = "${BASH_SOURCE[0]}" ]] && exit 1 || return 1
fi

[[ "$0" = "${BASH_SOURCE[0]}" ]] && exit 0 || return 0

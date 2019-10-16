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

# set -x

if [ -z "$(command -v ./setenv-android.sh)" ]; then
	echo "Failed to locate setenv-android.sh"
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
	PLATFORMS=(armeabi-v7a arm64-v8a x86 x86_64)
fi

# Thank god... one runtime and one compiler
RUNTIMES=(libc++)

for platform in "${PLATFORMS[@]}"
do
	for runtime in "${RUNTIMES[@]}"
	do
		make -f GNUmakefile-cross distclean > /dev/null 2>&1

		echo
		echo "===================================================================="
		echo "Testing for Android support of $platform using $runtime"

		# Test if we can set the environment for the platform
		if ! ./setenv-android.sh "$platform" "$runtime";
		then
			echo
			echo "There were problems testing $platform with $runtime"
			echo "$platform:$runtime ==> FAILURE" >> "$TMPDIR/build.log"

			touch "$TMPDIR/build.failed"
			continue
		fi

		echo
		echo "Building for $platform using $runtime..."
		echo

		# run in subshell to not keep any envars
		(
			source ./setenv-android.sh "$platform" "$runtime" # > /dev/null 2>&1
			if make -k -j "$MAKE_JOBS" -f GNUmakefile-cross static dynamic cryptest.exe;
			then
				echo "$platform:$runtime ==> SUCCESS" >> "$TMPDIR/build.log"
			else
				echo "$platform:$runtime ==> FAILURE" >> "$TMPDIR/build.log"
				touch "$TMPDIR/build.failed"
			fi
		)
	done
done

echo ""
echo "===================================================================="
echo "Dumping build results"
cat "$TMPDIR/build.log"

# let the script fail if any of the builds failed
if [ -f "$TMPDIR/build.failed" ]; then
	[[ "$0" = "${BASH_SOURCE[0]}" ]] && exit 1 || return 1
fi

[[ "$0" = "${BASH_SOURCE[0]}" ]] && exit 0 || return 0

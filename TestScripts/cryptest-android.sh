#!/usr/bin/env bash

#############################################################################
#
# This script tests Android cross-compiles using setenv-android.sh script.
#
# Written and placed in public domain by Jeffrey Walton and Uri Blumenthal.
#
# Crypto++ Library is copyrighted as a compilation and (as of version 5.6.2)
# licensed under the Boost Software License 1.0, while the individual files
# in the compilation are all public domain.
#
# See http://www.cryptopp.com/wiki/Android_(Command_Line) for more details
#
#############################################################################

# Error checking
if [ -z "$(command -v ./setenv-android.sh 2>/dev/null)" ]; then
    echo "Failed to locate setenv-android.sh."
    exit 1
fi

# Error checking
if [ ! -d "${ANDROID_NDK_ROOT}" ]; then
    echo "ERROR: ANDROID_NDK_ROOT is not a valid path for ${USER}. Please set it."
    echo "ANDROID_NDK_ROOT is '${ANDROID_NDK_ROOT}'"
    exit 1
fi

# Error checking
if [ ! -d "${ANDROID_SDK_ROOT}" ]; then
    echo "ERROR: ANDROID_SDK_ROOT is not a valid path for ${USER}. Please set it."
    echo "ANDROID_SDK_ROOT is '${ANDROID_SDK_ROOT}'"
    exit 1
fi

# Error checking
if [ -z "$(command -v ndk-build 2>/dev/null)"  ]; then
    echo "ERROR: ndk-build is not on-path for ${USER}. Please set it."
    echo "PATH is '${PATH}'"
    exit 1
fi

# Temp directory
if [[ -z "${TMPDIR}" ]]; then
    TMPDIR="$HOME/tmp"
    mkdir -p "${TMPDIR}"
    if [ -n "${SUDO_USER}" ]; then
        chown -R "${SUDO_USER}" "${TMPDIR}"
    fi
fi

# Sane default
if [[ -z "${MAKE_JOBS}" ]]; then
    MAKE_JOBS=4
fi

# Cleanup old artifacts
rm -rf "${TMPDIR}/build.failed" 2>/dev/null
rm -rf "${TMPDIR}/build.log" 2>/dev/null

#############################################################################

# Prepare the environment
unset CXX CPPFLAGS CXXFLAGS LDFLAGS
unset ANDROID_CPPFLAGS ANDROID_CXXFLAGS ANDROID_LDFLAGS ANDROID_SYSROOT

if [[ -e TestScripts/setenv-android.sh ]]; then
    cp TestScripts/setenv-android.sh .
    chmod u+x setenv-android.sh
fi

#############################################################################

PLATFORMS=(armv7a aarch64 x86 x86_64)

for platform in "${PLATFORMS[@]}"
do
    # setenv-android.sh reads these two variables for configuration info.
    # Android 5.0 is 21. Android 6.0 is 23.
    export ANDROID_API="23"
    export ANDROID_CPU="${platform}"

    make -f GNUmakefile-cross distclean > /dev/null 2>&1

    echo
    echo "===================================================================="
    echo "Testing for Android support of ${platform}"

    # Test if we can set the environment for the platform
    if ! ./setenv-android.sh > /dev/null 2>&1;
    then
        echo
        echo "There were problems testing ${platform}"
        echo "${platform} ==> SKIPPED" >> "${TMPDIR}/build.log"

        continue
    fi

    echo
    echo "===================================================================="
    echo "Building for ${platform}..."

    # run in subshell to not keep any envars
    (
        source ./setenv-android.sh
        if make -k -j "${MAKE_JOBS}" -f GNUmakefile-cross static dynamic cryptest.exe;
        then
            echo "${platform} ==> SUCCESS" >> "${TMPDIR}/build.log"
        else
            echo "${platform} ==> FAILURE" >> "${TMPDIR}/build.log"
            touch "${TMPDIR}/build.failed"
        fi

        # Test code generation
        if [[ "${platform}" == "armv7a" ]]
        then

            # Test NEON code generation
            # In the past we looked for the vector loads, stores and shifts using vld and friends.
            # It looks like objdump changed its output format on Android after Clang, so we need
            # to check for statements like eor v0.16b, v2.16b, v0.16b nowadays.
            count=$(${OBJDUMP} --disassemble aria_simd.o 2>&1 | grep -c -E 'vld|vst|vshl|vshr|veor|v0\.|v1\.|v2\.|v3\.|v4\.|v5\.|v6\.|v7\.')
            if [[ "${count}" -gt 64 ]]
            then
                echo "${platform} : NEON ==> SUCCESS" >> "${TMPDIR}/build.log"
            else
                echo "${platform} : NEON ==> FAILURE" >> "${TMPDIR}/build.log"
                touch "${TMPDIR}/build.failed"
            fi

        elif [[ "${platform}" == "aarch64" ]]
        then

            # Test ASIMD code generation
            # In the past we looked for the vector loads, stores and shifts using vld and friends.
            # It looks like objdump changed its output format on Android after Clang, so we need
            # to check for statements like eor v0.16b, v2.16b, v0.16b nowadays.
            count=$(${OBJDUMP} --disassemble aria_simd.o 2>&1 | grep -c -E 'vld|vst|vshl|vshr|veor|v0\.|v1\.|v2\.|v3\.|v4\.|v5\.|v6\.|v7\.')
            if [[ "${count}" -gt 64 ]]
            then
                echo "${platform} : ASIMD ==> SUCCESS" >> "${TMPDIR}/build.log"
            else
                echo "${platform} : ASIMD ==> FAILURE" >> "${TMPDIR}/build.log"
                touch "${TMPDIR}/build.failed"
            fi

            # Test AES code generation
            count=$(${OBJDUMP} --disassemble rijndael_simd.o 2>&1 | grep -c -E 'aese|aesd|aesmc|aesimc')
            if [[ "${count}" -gt 32 ]]
            then
                echo "${platform} : AES ==> SUCCESS" >> "${TMPDIR}/build.log"
            else
                echo "${platform} : AES ==> FAILURE" >> "${TMPDIR}/build.log"
                touch "${TMPDIR}/build.failed"
            fi

            # Test PMULL code generation
            count=$(${OBJDUMP} --disassemble gcm_simd.o 2>&1 | grep -c -E 'pmull|pmull2')
            if [[ "${count}" -gt 16 ]]
            then
                echo "${platform} : PMULL ==> SUCCESS" >> "${TMPDIR}/build.log"
            else
                echo "${platform} : PMULL ==> FAILURE" >> "${TMPDIR}/build.log"
                touch "${TMPDIR}/build.failed"
            fi

            # Test SHA1 code generation
            count=$(${OBJDUMP} --disassemble sha_simd.o 2>&1 | grep -c -E 'sha1c|sha1m|sha1p|sha1h|sha1su0|sha1su1')
            if [[ "${count}" -gt 32 ]]
            then
                echo "${platform} : SHA1 ==> SUCCESS" >> "${TMPDIR}/build.log"
            else
                echo "${platform} : SHA1 ==> FAILURE" >> "${TMPDIR}/build.log"
                touch "${TMPDIR}/build.failed"
            fi

            # Test SHA2 code generation
            count=$(${OBJDUMP} --disassemble sha_simd.o | grep -c -E 'sha256h|sha256su0|sha256su1')
            if [[ "${count}" -gt 32 ]]
            then
                echo "${platform} : SHA2 ==> SUCCESS" >> "${TMPDIR}/build.log"
            else
                echo "${platform} : SHA2 ==> FAILURE" >> "${TMPDIR}/build.log"
                touch "${TMPDIR}/build.failed"
            fi
        elif [[ "${platform}" == "x86" || "${platform}" == "x86_64" ]]
        then

            # Test AES code generation
            count=$(${OBJDUMP} --disassemble rijndael_simd.o 2>&1 | grep -c -E 'aesenc|aesdec|aesenclast|aesdeclast|aesimc')
            if [[ "${count}" -gt 32 ]]
            then
                echo "${platform} : AES ==> SUCCESS" >> "${TMPDIR}/build.log"
            else
                echo "${platform} : AES ==> FAILURE" >> "${TMPDIR}/build.log"
                touch "${TMPDIR}/build.failed"
            fi

            # Test CLMUL code generation
            count=$(${OBJDUMP} --disassemble gcm_simd.o 2>&1 | grep -c -E 'pclmulqdq|pclmullqlq|pclmullqhq|vpclmulqdq')
            if [[ "${count}" -gt 16 ]]
            then
                echo "${platform} : CLMUL ==> SUCCESS" >> "${TMPDIR}/build.log"
            else
                echo "${platform} : CLMUL ==> FAILURE" >> "${TMPDIR}/build.log"
                touch "${TMPDIR}/build.failed"
            fi

            # Test SHA1 code generation
            count=$(${OBJDUMP} --disassemble sha_simd.o 2>&1 | grep -c -E 'sha1rnds4|sha1nexte|sha1msg1|sha1msg2')
            if [[ "${count}" -gt 32 ]]
            then
                echo "${platform} : SHA1 ==> SUCCESS" >> "${TMPDIR}/build.log"
            else
                echo "${platform} : SHA1 ==> FAILURE" >> "${TMPDIR}/build.log"
                touch "${TMPDIR}/build.failed"
            fi

            # Test SHA2 code generation
            count=$(${OBJDUMP} --disassemble sha_simd.o | grep -c -E 'sha256rnds2|sha256msg1|sha256msg2')
            if [[ "${count}" -gt 32 ]]
            then
                echo "${platform} : SHA2 ==> SUCCESS" >> "${TMPDIR}/build.log"
            else
                echo "${platform} : SHA2 ==> FAILURE" >> "${TMPDIR}/build.log"
                touch "${TMPDIR}/build.failed"
            fi
        fi
    )
done

echo
echo "====================================================="
cat "${TMPDIR}/build.log"

# let the script fail if any of the builds failed
if [ -f "${TMPDIR}/build.failed" ]; then
    exit 1
fi

exit 0

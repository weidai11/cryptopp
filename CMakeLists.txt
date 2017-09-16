# Please ensure your changes or patch meets minimum requirements.
#   The minimum requirements are 2.8.5. They roughly equate to Ubuntu 12.04 LTS
#   Please do not check in something for 2.8.12 or 3.5.0. To test your changes,
#   please set up a Ubuntu 12.04 LTS system. Then, manually install Cmake 2.8.5
#   from http://cmake.org/Wiki/CMake_Released_Versions.

MESSAGE( STATUS
"*************************************************************************\n\
CMake support is being sunsetted. It is a redundant build system because\n\
the Makefile is used on Unix & Linux; and Visual Studio & MSBuild are used\n\
on Windows. Lack of Native CMake support for AIX, Android, iOS, PowerPC,\n\
Solaris, Windows Phone, Windows Store, SSE, ARMv7, ARMv8 and Power8 placed\n\
too much of a burden on the library maintainers. You can find the latest\n\
community maintained CmakeList.txt at http://www.cryptopp.com/wiki/CMake.\n\
-- *************************************************************************"
)

cmake_minimum_required(VERSION 2.8.5 FATAL_ERROR)

project(cryptopp)

# Make RelWithDebInfo the default (it does e.g. add '-O2 -g -DNDEBUG' for GNU)
#   If not in multi-configuration environments, no explicit build type or CXX
#   flags are set by the user and if we are the root CMakeLists.txt file.
if (NOT CMAKE_CONFIGURATION_TYPES AND
    NOT CMAKE_NO_BUILD_TYPE AND
    NOT CMAKE_BUILD_TYPE AND
    NOT CMAKE_CXX_FLAGS AND
    CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
	set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif ()

set(cryptopp_VERSION_MAJOR 6)
set(cryptopp_VERSION_MINOR 0)
set(cryptopp_VERSION_PATCH 0)

include(GNUInstallDirs)
include(CheckCXXCompilerFlag)

#============================================================================
# Settable options
#============================================================================

option(BUILD_STATIC "Build static library" ON)
option(BUILD_SHARED "Build shared library" ON)
option(BUILD_TESTING "Build library tests" ON)
option(BUILD_DOCUMENTATION "Use Doxygen to create the HTML based API documentation" OFF)
option(USE_INTERMEDIATE_OBJECTS_TARGET "Use a common intermediate objects target for the static and shared library targets" ON)

if (CMAKE_VERSION VERSION_LESS 2.8.8 AND USE_INTERMEDIATE_OBJECTS_TARGET)
  message(STATUS "Forcing USE_INTERMEDIATE_OBJECTS_TARGET to OFF - requires CMake >= 2.8.8")
  set(USE_INTERMEDIATE_OBJECTS_TARGET OFF CACHE BOOL "Use a common intermediate objects target for the static and shared library targets" FORCE)
endif ()

option(DISABLE_ASM "Disable ASM" OFF)
option(DISABLE_SSSE3 "Disable SSSE3" OFF)
option(DISABLE_SSE4 "Disable SSE4" OFF)
option(DISABLE_AESNI "Disable AES-NI" OFF)
option(DISABLE_SHA "Disable SHA" OFF)
option(CRYPTOPP_NATIVE_ARCH "Enable native architecture" OFF)
set(CRYPTOPP_DATA_DIR "" CACHE PATH "Crypto++ test data directory")

#============================================================================
# Internal compiler options
#============================================================================

# Stop hiding the damn output...
# set(CMAKE_VERBOSE_MAKEFILE on)

# Always 1 ahead in Master. Also see http://groups.google.com/forum/#!topic/cryptopp-users/SFhqLDTQPG4
set(LIB_VER ${cryptopp_VERSION_MAJOR}${cryptopp_VERSION_MINOR}${cryptopp_VERSION_PATCH})

# Don't use RPATH's. The resulting binary could fail a security audit.
if (NOT CMAKE_VERSION VERSION_LESS 2.8.12)
  set(CMAKE_MACOSX_RPATH 0)
endif ()

if (CMAKE_CXX_COMPILER_ID STREQUAL "Intel")
	add_definitions(-wd68 -wd186 -wd279 -wd327 -wd161 -wd3180)
endif ()

# Also see http://github.com/weidai11/cryptopp/issues/395
if (DISABLE_ASM)
	add_definitions(-DCRYPTOPP_DISABLE_ASM)
endif ()
if (DISABLE_SSSE3)
	add_definitions(-DCRYPTOPP_DISABLE_SSSE3)
endif ()
if (DISABLE_SSE4)
	add_definitions(-DCRYPTOPP_DISABLE_SSE4)
endif ()
if (DISABLE_AESNI)
	add_definitions(-DCRYPTOPP_DISABLE_AESNI)
endif ()
if (DISABLE_SHA)
	add_definitions(-DCRYPTOPP_DISABLE_SHA)
endif ()
if (NOT CRYPTOPP_DATA_DIR STREQUAL "")
	add_definitions(-DCRYPTOPP_DATA_DIR="${CRYPTOPP_DATA_DIR}")
endif ()

# CRYPTOPP_NATIVE_ARCH is set below once we know what it means to be "native"

###############################################################################

# Try to find a Posix compatible grep and sed. Solaris, Digital Unix,
#   Tru64, HP-UX and a few others need tweaking

if (${CMAKE_SYSTEM_NAME} STREQUAL "SunOS")
	set(GREP_CMD /usr/xpg4/bin/grep)
	set(SED_CMD /usr/xpg4/bin/sed)
else()
	set(GREP_CMD grep)
	set(SED_CMD sed)
endif ()

###############################################################################

function(CheckCompilerOption opt var)

	if (CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")

		# CMake does not provide a generic shell/terminal mechanism
		#  and Microsoft environments don't know what 'sh' is.
		set(${var} 0 PARENT_SCOPE)

	elseif (CMAKE_CXX_COMPILER_ID STREQUAL "SunPro")

		message(STATUS "Performing Test ${var}")
		execute_process(
			COMMAND sh -c "${CMAKE_CXX_COMPILER} ${CMAKE_CXX_FLAGS} ${opt} -E -xdumpmacros /dev/null 2>&1"
			COMMAND ${GREP_CMD} -i -c -E "illegal value ignored"
			RESULT_VARIABLE COMMAND_RESULT
			OUTPUT_VARIABLE COMMAND_OUTPUT
			OUTPUT_STRIP_TRAILING_WHITESPACE)

		# No dereference below. Thanks for the warning, CMake (not!).
		if (COMMAND_RESULT AND NOT COMMAND_OUTPUT)
			set(${var} 1 PARENT_SCOPE)
			message(STATUS "Performing Test ${var} - Success")
		else ()
			set(${var} 0 PARENT_SCOPE)
			message(STATUS "Performing Test ${var} - Failed")
		endif ()

	else ()

		CHECK_CXX_COMPILER_FLAG(${opt} ${var})

	endif ()

endfunction(CheckCompilerOption)

###############################################################################

function(DumpMachine output pattern)

	if (CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")

		# CMake does not provide a generic shell/terminal mechanism
		#  and Microsoft environments don't know what 'sh' is.
		set(${output} 0 PARENT_SCOPE)

	else ()

		execute_process(
			COMMAND sh -c "${CMAKE_CXX_COMPILER} -dumpmachine 2>&1"
			COMMAND ${GREP_CMD} -i -c -E "${pattern}"
			OUTPUT_VARIABLE ${output}
			OUTPUT_STRIP_TRAILING_WHITESPACE)
		set(${output} "${${output}}" PARENT_SCOPE)

	endif()

endfunction(DumpMachine)

# Thansk to Anonimal for MinGW; see http://github.com/weidai11/cryptopp/issues/466
DumpMachine(CRYPTOPP_AMD64 "amd64|x86_64")
DumpMachine(CRYPTOPP_I386 "i.86")
DumpMachine(CRYPTOPP_MINGW32 "\\<mingw32\\>")
DumpMachine(CRYPTOPP_MINGW64 "w64-mingw32|mingw64")
DumpMachine(CRYPTOPP_X32 "x32")
DumpMachine(CRYPTOPP_AARCH32 "Aarch32")
DumpMachine(CRYPTOPP_AARCH64 "Aarch64")
DumpMachine(CRYPTOPP_ARMHF "armhf|arm7l|eabihf")
DumpMachine(CRYPTOPP_ARM "\\<arm\\>")

###############################################################################

# Test SunCC for a string like 'CC: Sun C++ 5.13 SunOS_i386'
if (NOT CRYPTOPP_SOLARIS)
	execute_process(COMMAND sh -c "${CMAKE_CXX_COMPILER} -V 2>&1"
		COMMAND ${GREP_CMD} -i -c "SunOS"
		OUTPUT_VARIABLE CRYPTOPP_SOLARIS
		OUTPUT_STRIP_TRAILING_WHITESPACE)
endif ()

# Test GCC for a string like 'i386-pc-solaris2.11'
if (NOT CRYPTOPP_SOLARIS)
	execute_process(COMMAND sh -c "${CMAKE_CXX_COMPILER} -dumpmachine 2>&1"
		COMMAND ${GREP_CMD} -i -c "Solaris"
		OUTPUT_VARIABLE CRYPTOPP_SOLARIS
		OUTPUT_STRIP_TRAILING_WHITESPACE)
endif ()

# DumpMachine SunCC style
if (CMAKE_CXX_COMPILER_ID STREQUAL "SunPro")

	# SunCC is 32-bit, but it builds both 32 and 64 bit. Use
	execute_process(COMMAND sh -c "${CMAKE_CXX_COMPILER} -V 2>&1"
		COMMAND ${GREP_CMD} -i -c "Sparc"
		OUTPUT_VARIABLE CRYPTOPP_SPARC
		OUTPUT_STRIP_TRAILING_WHITESPACE)

	execute_process(COMMAND sh -c "${CMAKE_CXX_COMPILER} -V 2>&1"
		COMMAND ${GREP_CMD} -i -c -E "i386|i86"
		OUTPUT_VARIABLE CRYPTOPP_I386
		OUTPUT_STRIP_TRAILING_WHITESPACE)

	execute_process(COMMAND isainfo -k
		COMMAND ${GREP_CMD} -i -c "i386"
		OUTPUT_VARIABLE KERNEL_I386
		OUTPUT_STRIP_TRAILING_WHITESPACE)

	execute_process(COMMAND isainfo -k
		COMMAND ${GREP_CMD} -i -c "amd64"
		OUTPUT_VARIABLE KERNEL_AMD64
		OUTPUT_STRIP_TRAILING_WHITESPACE)

	execute_process(COMMAND isainfo -k
		COMMAND ${GREP_CMD} -i -c "Sparc"
		OUTPUT_VARIABLE KERNEL_SPARC
		OUTPUT_STRIP_TRAILING_WHITESPACE)

	execute_process(COMMAND isainfo -k
		COMMAND ${GREP_CMD} -i -c -E "UltraSarc|Sparc64|SparcV9"
		OUTPUT_VARIABLE KERNEL_SPARC64
		OUTPUT_STRIP_TRAILING_WHITESPACE)

	# Build for 32-bit on 64-bit kernels unless Native Arch is
	#  specified. Note that this is a policy provided by Sun.
	if (CRYPTOPP_NATIVE_ARCH AND KERNEL_I386)
		unset(CRYPTOPP_AMD64)
		set(CRYPTOPP_I386 1)
	elseif (CRYPTOPP_NATIVE_ARCH AND KERNEL_AMD64)
		unset(CRYPTOPP_I386)
		set(CRYPTOPP_AMD64 1)
	elseif (CRYPTOPP_NATIVE_ARCH AND KERNEL_SPARC)
		unset(KERNEL_SPARC64)
		set(KERNEL_SPARC 1)
	elseif (CRYPTOPP_NATIVE_ARCH AND KERNEL_SPARC64)
		unset(KERNEL_SPARC)
		set(KERNEL_SPARC64 1)
	endif ()
endif ()

###############################################################################

if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")

	execute_process(COMMAND sh -c "${CMAKE_CXX_COMPILER} --version 2>&1"
		COMMAND ${GREP_CMD} -i -c "macports"
		OUTPUT_VARIABLE MACPORTS
		OUTPUT_STRIP_TRAILING_WHITESPACE)

	if (MACPORTS EQUAL 0)
		# Get GAS version, add defs + set as appropriate
		set(GAS_CMD sh -c "${CMAKE_CXX_COMPILER} -xc -c /dev/null -Wa,-v -o/dev/null 2>&1")

		execute_process(COMMAND ${GAS_CMD}
			OUTPUT_VARIABLE GAS_STRING
			OUTPUT_STRIP_TRAILING_WHITESPACE)
		string(FIND ${GAS_STRING} "GNU assumbler" GAS_OUTPUT)

		if (GAS_OUTPUT)
			#.intel_syntax wasn't supported until GNU assembler 2.10

			# TODO(unassigned): string() REGEX was not cooperating at time of writing. Re-implement as needed.
			execute_process(COMMAND echo ${GAS_STRING}
				COMMAND ${GREP_CMD} -i -c -E "GNU assembler version (2\\.[1-9][0-9]|[3-9])"
				OUTPUT_VARIABLE GAS210_OR_LATER)
			if (GAS210_OR_LATER EQUAL 0)
				add_definitions(-DCRYPTOPP_DISABLE_ASM)
				set(DISABLE_ASM 1)
			endif ()

			execute_process(COMMAND echo ${GAS_STRING}
				COMMAND ${GREP_CMD} -i -c -E "GNU assembler version (2\\.1[7-9]|2\\.[2-9]|[3-9])"
				OUTPUT_VARIABLE GAS217_OR_LATER)
			if (GAS217_OR_LATER EQUAL 0)
				add_definitions(-DCRYPTOPP_DISABLE_SSSE3)
				set(DISABLE_SSSE3 1)
			endif ()

			# OpenBSD and CentOS 5 needed this one due to ARIA and BLAKE2
			execute_process(COMMAND echo ${GAS_STRING}
				COMMAND ${GREP_CMD} -i -c -E "GNU assembler version (2\\.1[8-9]|2\\.[2-9]|[3-9])"
				OUTPUT_VARIABLE GAS218_OR_LATER)
			if (GAS218_OR_LATER EQUAL 0)
				add_definitions(-DCRYPTOPP_DISABLE_SSE4)
				set(DISABLE_SSE4 1)
			endif ()

			execute_process(COMMAND echo ${GAS_STRING}
				COMMAND ${GREP_CMD} -i -c -E "GNU assembler version (2\\.19|2\\.[2-9]|[3-9])"
				OUTPUT_VARIABLE GAS219_OR_LATER)
			if (GAS219_OR_LATER EQUAL 0)
				add_definitions(-DCRYPTOPP_DISABLE_AESNI)
				set(DISABLE_AESNI 1)
			endif ()

			# Ubuntu 10 and Ubuntu 12 needed this one
			execute_process(COMMAND echo ${GAS_STRING}
				COMMAND ${GREP_CMD} -i -c -E "GNU assembler version (2\\.2[3-9]|2\\.[3-9]|[3-9])"
				OUTPUT_VARIABLE GAS223_OR_LATER)
			if (GAS223_OR_LATER EQUAL 0)
				add_definitions(-DCRYPTOPP_DISABLE_SHA)
				set(DISABLE_SHA 1)
			endif ()
		endif ()
	endif ()
endif ()

# TODO: what about ICC and LLVM on Windows?
if (CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
	if (CMAKE_SYSTEM_VERSION MATCHES "10\\.0.*")
		SET( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /D\"_WIN32_WINNT=0x0A00\"" )
	endif ()
	SET( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /FI\"winapifamily.h\"" )
endif ()

# Enable PIC for all target machines except 32-bit i386 due to register pressures.
if (NOT CRYPTOPP_I386)
	SET(CMAKE_POSITION_INDEPENDENT_CODE 1)
endif ()

# Solaris specific
if (CRYPTOPP_SOLARIS)

	# Determine 32-bit vs 64-bit
	if (CRYPTOPP_AMD64 OR CRYPTOPP_SPARC64)
		SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -m64")
	else ()
		SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -m32")
	endif ()

	# SunCC needs -template=no%extdef
	if (CMAKE_CXX_COMPILER_ID STREQUAL "SunPro")
		SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -template=no%extdef")
	endif ()

	# GCC needs to enable use of '/'
	if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
		set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wa,--divide")
	endif ()

endif ()

# Link is driven through the compiler, but CXXFLAGS are not used. Also see
#   http://public.kitware.com/pipermail/cmake/2003-June/003967.html
if (NOT (WINDOWS OR WINDOWS_STORE OR WINDOWS_PHONE))
	SET(CMAKE_CXX_LINK_FLAGS "${CMAKE_CXX_FLAGS}")
endif ()

#============================================================================
# Sources & headers
#============================================================================

# Library headers
file(GLOB cryptopp_HEADERS *.h)
# Remove headers used to build test suite
list(REMOVE_ITEM cryptopp_HEADERS
		${CMAKE_CURRENT_SOURCE_DIR}/bench.h
		${CMAKE_CURRENT_SOURCE_DIR}/validate.h
		)

# Test sources. You can use the GNUmakefile to generate the list: `make sources`.
file(GLOB cryptopp_SOURCES_TEST test.cpp bench1.cpp bench2.cpp validat0.cpp validat1.cpp validat2.cpp validat3.cpp adhoc.cpp datatest.cpp regtest1.cpp regtest2.cpp regtest3.cpp fipsalgt.cpp dlltest.cpp fipstest.cpp)

# Library sources. You can use the GNUmakefile to generate the list: `make sources`.
# Makefile sorted them at http://github.com/weidai11/cryptopp/pull/426.
file(GLOB cryptopp_SOURCES *.cpp)
list(SORT cryptopp_SOURCES)
list(REMOVE_ITEM cryptopp_SOURCES
		${CMAKE_CURRENT_SOURCE_DIR}/cryptlib.cpp
		${CMAKE_CURRENT_SOURCE_DIR}/cpu.cpp
		${CMAKE_CURRENT_SOURCE_DIR}/integer.cpp
		${CMAKE_CURRENT_SOURCE_DIR}/pch.cpp
		${CMAKE_CURRENT_SOURCE_DIR}/simple.cpp
		${CMAKE_CURRENT_SOURCE_DIR}/winpipes.cpp
		${CMAKE_CURRENT_SOURCE_DIR}/cryptlib_bds.cpp
		${cryptopp_SOURCES_TEST}
		)
set(cryptopp_SOURCES
		${CMAKE_CURRENT_SOURCE_DIR}/cryptlib.cpp
		${CMAKE_CURRENT_SOURCE_DIR}/cpu.cpp
		${CMAKE_CURRENT_SOURCE_DIR}/integer.cpp
		${cryptopp_SOURCES}
		)

if (MINGW OR WIN32)
	list(APPEND cryptopp_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/winpipes.cpp)
endif ()

if (MSVC AND NOT DISABLE_ASM)
	if (${CMAKE_GENERATOR} MATCHES ".*ARM")
		message(STATUS "Disabling ASM because ARM is specified as target platform.")
	else ()
		if (CMAKE_SIZEOF_VOID_P EQUAL 8)
			list(APPEND cryptopp_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/x64dll.asm)
			list(APPEND cryptopp_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/x64masm.asm)
			set_source_files_properties(${CMAKE_CURRENT_SOURCE_DIR}/x64dll.asm PROPERTIES COMPILE_FLAGS "/D_M_X64")
			set_source_files_properties(${CMAKE_CURRENT_SOURCE_DIR}/x64masm.asm PROPERTIES COMPILE_FLAGS "/D_M_X64")
			set_source_files_properties(${CMAKE_CURRENT_SOURCE_DIR}/rdrand.asm PROPERTIES COMPILE_FLAGS "/D_M_X64")
		else ()
			set_source_files_properties(${CMAKE_CURRENT_SOURCE_DIR}/x64dll.asm PROPERTIES COMPILE_FLAGS "/D_M_X86 /safeseh")
			set_source_files_properties(${CMAKE_CURRENT_SOURCE_DIR}/x64masm.asm PROPERTIES COMPILE_FLAGS "/D_M_X86 /safeseh")
			set_source_files_properties(${CMAKE_CURRENT_SOURCE_DIR}/rdrand.asm PROPERTIES COMPILE_FLAGS "/D_M_X86 /safeseh")
		endif ()
		list(APPEND cryptopp_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/rdrand.asm)
		enable_language(ASM_MASM)
	endif ()
endif ()

#============================================================================
# Architecture flags
#============================================================================

# New as of Pull Request 461, http://github.com/weidai11/cryptopp/pull/461.
if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang" OR CMAKE_CXX_COMPILER_ID STREQUAL "GNU")

	if (CRYPTOPP_AMD64 OR CRYPTOPP_I386 OR CRYPTOPP_X32)

		CheckCompilerOption("-mssse3" CRYPTOPP_IA32_SSSE3)
		CheckCompilerOption("-msse4.2" CRYPTOPP_IA32_SSE4)
		CheckCompilerOption("-mssse3 -mpclmul" CRYPTOPP_IA32_CLMUL)
		CheckCompilerOption("-msse4.1 -maes" CRYPTOPP_IA32_AES)
		CheckCompilerOption("-msse4.2 -msha" CRYPTOPP_IA32_SHA)
		CheckCompilerOption("-march=native" CRYPTOPP_IA32_NATIVE)

		# Deferred native arch; added to all CXXFLAGS
		if (CRYPTOPP_NATIVE_ARCH AND CRYPTOPP_IA32_NATIVE)
			set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -march=native")
		elseif (CRYPTOPP_NATIVE_ARCH)
			message(WARNING "CRYPTOPP_NATIVE_ARCH enabled, but failed to detect native architecture")
		endif ()

		if (CRYPTOPP_IA32_SSSE3 AND NOT DISABLE_SSSE3)
			set_source_files_properties(aria-simd.cpp PROPERTIES COMPILE_FLAGS "-mssse3")
			if (CRYPTOPP_IA32_SSE4 AND NOT DISABLE_SSE4)
				set_source_files_properties(blake2-simd.cpp PROPERTIES COMPILE_FLAGS "-msse4.2")
				set_source_files_properties(crc-simd.cpp PROPERTIES COMPILE_FLAGS "-msse4.2")
				if (CRYPTOPP_IA32_CLMUL AND NOT DISABLE_AES)
					set_source_files_properties(gcm-simd.cpp PROPERTIES COMPILE_FLAGS "-mssse3 -mpclmul")
				endif ()
				if (CRYPTOPP_IA32_AES AND NOT DISABLE_AES)
					set_source_files_properties(rijndael-simd.cpp PROPERTIES COMPILE_FLAGS "-msse4.1 -maes")
				endif ()
				if (CRYPTOPP_IA32_SHA AND NOT DISABLE_SHA)
					set_source_files_properties(sha-simd.cpp PROPERTIES COMPILE_FLAGS "-msse4.2 -msha")
					set_source_files_properties(shacal2-simd.cpp PROPERTIES COMPILE_FLAGS "-msse4.2 -msha")
				endif ()
			endif ()
		endif ()

	elseif (CRYPTOPP_AARCH32 OR CRYPTOPP_AARCH64)

		CheckCompilerOption("-march=armv8-a" CRYPTOPP_ARMV8A_BASE)
		CheckCompilerOption("-march=armv8-a+crc" CRYPTOPP_ARMV8A_CRC)
		CheckCompilerOption("-march=armv8-a+crypto" CRYPTOPP_ARMV8A_CRYPTO)
		CheckCompilerOption("-march=armv8-a" CRYPTOPP_ARMV8A_NATIVE)

		# Deferred native arch; added to all CXXFLAGS
		if (CRYPTOPP_NATIVE_ARCH AND CRYPTOPP_ARMV8A_NATIVE)
			set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -march=armv8-a")
		elseif (CRYPTOPP_NATIVE_ARCH)
			message(WARNING "CRYPTOPP_NATIVE_ARCH enabled, but failed to detect native architecture")
		endif ()

		if (CRYPTOPP_ARMV8A_BASE)
			set_source_files_properties(aria-simd.cpp PROPERTIES COMPILE_FLAGS "-march=armv8-a")
			set_source_files_properties(blake2-simd.cpp PROPERTIES COMPILE_FLAGS "-march=armv8-a")
			set_source_files_properties(neon-simd.cpp PROPERTIES COMPILE_FLAGS "-march=armv8-a")
		endif ()
		if (CRYPTOPP_ARMV8A_CRC)
			set_source_files_properties(crc-simd.cpp PROPERTIES COMPILE_FLAGS "-march=armv8-a+crc")
		endif ()
		if (CRYPTOPP_ARMV8A_CRYPTO)
			set_source_files_properties(gcm-simd.cpp PROPERTIES COMPILE_FLAGS "-march=armv8-a+crypto")
			set_source_files_properties(rijndael-simd.cpp PROPERTIES COMPILE_FLAGS "-march=armv8-a+crypto")
			set_source_files_properties(sha-simd.cpp PROPERTIES COMPILE_FLAGS "-march=armv8-a+crypto")
			set_source_files_properties(shacal2-simd.cpp PROPERTIES COMPILE_FLAGS "-march=armv8-a+crypto")
		endif ()

	elseif (CRYPTOPP_ARM OR CRYPTOPP_ARMHF)

		CheckCompilerOption("-march=armv7-a -mfpu=neon" CRYPTOPP_ARMV7A_NEON)
		CheckCompilerOption("-march=armv7-a -mfloat-abi=hard" CRYPTOPP_ARMV7A_HARD)
		CheckCompilerOption("-march=armv7-a -mfloat-abi=softfp" CRYPTOPP_ARMV7A_SOFTFP)

		# Deferred native arch; added to all CXXFLAGS
		if (CRYPTOPP_NATIVE_ARCH AND CRYPTOPP_ARMV7A_HARD)
			set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -march=armv7-a -mfloat-abi=hard -mfpu=neon")
		elseif (CRYPTOPP_NATIVE_ARCH AND CRYPTOPP_ARMV7A_SOFTFP)
			set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -march=armv7-a -mfloat-abi=softfp -mfpu=neon")
		elseif (CRYPTOPP_NATIVE_ARCH)
			message(WARNING "CRYPTOPP_NATIVE_ARCH enabled, but failed to detect native architecture")
		endif ()

		if (CRYPTOPP_ARMV7A_HARD AND CRYPTOPP_ARMV7A_NEON)
			# Need to set floating point ABI to something, like "hard" of "softfp". Most Linux use hard floats ("hard").
			set_source_files_properties(aria-simd.cpp PROPERTIES COMPILE_FLAGS "-march=armv7-a -mfloat-abi=hard -mfpu=neon")
			set_source_files_properties(blake2-simd.cpp PROPERTIES COMPILE_FLAGS "-march=armv7-a -mfloat-abi=hard -mfpu=neon")
			set_source_files_properties(gcm-simd.cpp PROPERTIES COMPILE_FLAGS "-march=armv7-a -mfloat-abi=hard -mfpu=neon")
			set_source_files_properties(neon-simd.cpp PROPERTIES COMPILE_FLAGS "-mfloat-abi=hard -mfpu=neon")
		elseif (CRYPTOPP_ARMV7A_SOFTFP AND CRYPTOPP_ARMV7A_NEON)
			# Need to set floating point ABI to something, like "hard" of "softfp". Most Linux use hard floats ("hard").
			set_source_files_properties(aria-simd.cpp PROPERTIES COMPILE_FLAGS "-march=armv7-a -mfloat-abi=softfp -mfpu=neon")
			set_source_files_properties(blake2-simd.cpp PROPERTIES COMPILE_FLAGS "-march=armv7-a -mfloat-abi=softfp -mfpu=neon")
			set_source_files_properties(gcm-simd.cpp PROPERTIES COMPILE_FLAGS "-march=armv7-a -mfloat-abi=softfp -mfpu=neon")
			set_source_files_properties(neon-simd.cpp PROPERTIES COMPILE_FLAGS "-mfloat-abi=softfp -mfpu=neon")
		endif ()
	endif ()
endif ()

# New as of Pull Request 461, http://github.com/weidai11/cryptopp/pull/461.
if (CMAKE_CXX_COMPILER_ID STREQUAL "SunPro")

	if (CRYPTOPP_AMD64 OR CRYPTOPP_I386 OR CRYPTOPP_X32)

		CheckCompilerOption("-xarch=ssse3" CRYPTOPP_IA32_SSSE3)
		CheckCompilerOption("-xarch=sse4_2" CRYPTOPP_IA32_SSE4)
		CheckCompilerOption("-xarch=aes" CRYPTOPP_IA32_CLMUL)
		CheckCompilerOption("-xarch=aes" CRYPTOPP_IA32_AES)
		CheckCompilerOption("-xarch=sha" CRYPTOPP_IA32_SHA)
		CheckCompilerOption("-native" CRYPTOPP_IA32_NATIVE)

		# Deferred native arch; added to all CXXFLAGS
		if (CRYPTOPP_NATIVE_ARCH AND CRYPTOPP_IA32_NATIVE)
			set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -native")
		elseif (CRYPTOPP_NATIVE_ARCH)
			message(WARNING "CRYPTOPP_NATIVE_ARCH enabled, but failed to detect native architecture")
		endif ()

		if (CRYPTOPP_IA32_SSSE3 AND NOT DISABLE_SSSE3)
			set_source_files_properties(aria-simd.cpp PROPERTIES COMPILE_FLAGS "-xarch=ssse3")
			if (CRYPTOPP_IA32_SSE4 AND NOT DISABLE_SSE4)
				set_source_files_properties(blake2-simd.cpp PROPERTIES COMPILE_FLAGS "-xarch=sse4_2")
				set_source_files_properties(crc-simd.cpp PROPERTIES COMPILE_FLAGS "-xarch=sse4_2")
				if (CRYPTOPP_IA32_CLMUL AND NOT DISABLE_AES)
					set_source_files_properties(gcm-simd.cpp PROPERTIES COMPILE_FLAGS "-xarch=aes")
				endif ()
				if (CRYPTOPP_IA32_AES AND NOT DISABLE_AES)
					set_source_files_properties(rijndael-simd.cpp PROPERTIES COMPILE_FLAGS "-xarch=aes")
				endif ()
				if (CRYPTOPP_IA32_SHA AND NOT DISABLE_SHA)
					set_source_files_properties(sha-simd.cpp PROPERTIES COMPILE_FLAGS "-xarch=sha")
					set_source_files_properties(shacal2-simd.cpp PROPERTIES COMPILE_FLAGS "-xarch=sha")
				endif ()
			endif ()
		endif ()

	elseif (CRYPTOPP_SPARC OR CRYPTOPP_SPARC64)

		# Sparc's need -xmemalign=4i
		CheckCompilerOption("-xmemalign=4i" CRYPTOPP_SUN_MEMALIGN)

		if (CRYPTOPP_SUN_MEMALIGN STREQUAL "1")
			set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -xmemalign=4i")
		endif ()

		# Deferred native arch; added to all CXXFLAGS
		if (CRYPTOPP_NATIVE_ARCH AND CRYPTOPP_SPARC_NATIVE)
			set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -native")
		elseif (CRYPTOPP_NATIVE_ARCH)
			message(WARNING "CRYPTOPP_NATIVE_ARCH enabled, but failed to detect native architecture")
		endif ()

	endif ()
endif ()

#============================================================================
# Compile targets
#============================================================================

# Set global includes BEFORE adding any targets for legacy CMake versions
if (CMAKE_VERSION VERSION_LESS 2.8.12)
	include_directories("${CMAKE_CURRENT_SOURCE_DIR}")
endif ()

if (USE_INTERMEDIATE_OBJECTS_TARGET)
	add_library(cryptopp-object OBJECT ${cryptopp_SOURCES})
endif ()

if (BUILD_STATIC)
	if (USE_INTERMEDIATE_OBJECTS_TARGET)
		add_library(cryptopp-static STATIC $<TARGET_OBJECTS:cryptopp-object>)
	else ()
		add_library(cryptopp-static STATIC ${cryptopp_SOURCES})
	endif ()

	if (NOT CMAKE_VERSION VERSION_LESS 2.8.12)
		target_include_directories(cryptopp-static PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}> $<INSTALL_INTERFACE:include/cryptopp>)
	endif ()
endif ()

if (BUILD_SHARED)
	if (USE_INTERMEDIATE_OBJECTS_TARGET)
		add_library(cryptopp-shared SHARED $<TARGET_OBJECTS:cryptopp-object>)
	else ()
		add_library(cryptopp-shared SHARED ${cryptopp_SOURCES})
	endif ()

	if (NOT CMAKE_VERSION VERSION_LESS 2.8.12)
		target_include_directories(cryptopp-shared PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}> $<INSTALL_INTERFACE:include/cryptopp>)
	endif ()
endif ()

# Set filenames for targets to be "cryptopp"
if (NOT MSVC)
	set(COMPAT_VERSION ${cryptopp_VERSION_MAJOR}.${cryptopp_VERSION_MINOR})

	if (BUILD_STATIC)
		set_target_properties(cryptopp-static
				PROPERTIES
				OUTPUT_NAME cryptopp)
	endif ()
	if (BUILD_SHARED)
		set_target_properties(cryptopp-shared
				PROPERTIES
				SOVERSION ${COMPAT_VERSION}
				OUTPUT_NAME cryptopp)
	endif ()
endif ()

# Targets, compatible with Crypto++ GNUMakefile
if (BUILD_STATIC)
	add_custom_target(static)
	add_dependencies(static cryptopp-static)
endif ()
if (BUILD_SHARED)
	add_custom_target(dynamic)
	add_dependencies(dynamic cryptopp-shared)
endif ()

#============================================================================
# Third-party libraries
#============================================================================

if (WIN32)
	if (BUILD_STATIC)
		target_link_libraries(cryptopp-static ws2_32)
	endif ()
	if (BUILD_SHARED)
		target_link_libraries(cryptopp-shared ws2_32)
	endif ()
endif ()

# This may need to be expanded to "Solaris"
if (CRYPTOPP_SOLARIS)
	if (BUILD_STATIC)
		target_link_libraries(cryptopp-static nsl socket)
	endif ()
	if (BUILD_SHARED)
		target_link_libraries(cryptopp-shared nsl socket)
	endif ()
endif ()

find_package(Threads)
if (BUILD_STATIC)
	target_link_libraries(cryptopp-static ${CMAKE_THREAD_LIBS_INIT})
endif ()
if (BUILD_SHARED)
	target_link_libraries(cryptopp-shared ${CMAKE_THREAD_LIBS_INIT})
endif ()

#============================================================================
# Tests
#============================================================================

enable_testing()
if (BUILD_TESTING)
	add_executable(cryptest ${cryptopp_SOURCES_TEST})
	target_link_libraries(cryptest cryptopp-static)

	# Setting "cryptest" binary name to "cryptest.exe"
	if (NOT (WIN32 OR CYGWIN))
		set_target_properties(cryptest PROPERTIES OUTPUT_NAME cryptest.exe)
	endif ()
	if (NOT TARGET cryptest.exe)
		add_custom_target(cryptest.exe)
		add_dependencies(cryptest.exe cryptest)
	endif ()

	file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/TestData DESTINATION ${PROJECT_BINARY_DIR})
	file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/TestVectors DESTINATION ${PROJECT_BINARY_DIR})

	add_test(NAME build_cryptest COMMAND "${CMAKE_COMMAND}" --build ${CMAKE_BINARY_DIR} --target cryptest)
	add_test(NAME cryptest COMMAND $<TARGET_FILE:cryptest> v)
	set_tests_properties(cryptest PROPERTIES DEPENDS build_cryptest)
endif ()

#============================================================================
# Doxygen documentation
#============================================================================

if (BUILD_DOCUMENTATION)
	find_package(Doxygen REQUIRED)

	set(in_source_DOCS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/html-docs")
	set(out_source_DOCS_DIR "${PROJECT_BINARY_DIR}/html-docs")

	add_custom_target(docs ALL
			COMMAND ${DOXYGEN_EXECUTABLE} Doxyfile -d CRYPTOPP_DOXYGEN_PROCESSING
			WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
			SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile
			)

	if (NOT ${in_source_DOCS_DIR} STREQUAL ${out_source_DOCS_DIR})
		add_custom_command(
				TARGET docs POST_BUILD
				COMMAND ${CMAKE_COMMAND} -E copy_directory "${in_source_DOCS_DIR}" "${out_source_DOCS_DIR}"
				COMMAND ${CMAKE_COMMAND} -E remove_directory "${in_source_DOCS_DIR}"
		)
	endif ()
endif ()

#============================================================================
# Install
#============================================================================

set(export_name "cryptopp-targets")

# Runtime package
if (BUILD_SHARED)
	install(
			TARGETS cryptopp-shared
			EXPORT ${export_name}
			DESTINATION ${CMAKE_INSTALL_LIBDIR}
			RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
			LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
			ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
	)
endif ()

# Development package
if (BUILD_STATIC)
	install(TARGETS cryptopp-static EXPORT ${export_name} DESTINATION ${CMAKE_INSTALL_LIBDIR})
endif ()
install(FILES ${cryptopp_HEADERS} DESTINATION include/cryptopp)

# CMake Package
if (NOT CMAKE_VERSION VERSION_LESS 2.8.8)	# CMakePackageConfigHelpers is supported from 2.8.8
	include(CMakePackageConfigHelpers)
	write_basic_package_version_file("${PROJECT_BINARY_DIR}/cryptopp-config-version.cmake" VERSION ${cryptopp_VERSION_MAJOR}.${cryptopp_VERSION_MINOR}.${cryptopp_VERSION_PATCH} COMPATIBILITY SameMajorVersion)
	install(FILES cryptopp-config.cmake ${PROJECT_BINARY_DIR}/cryptopp-config-version.cmake DESTINATION "lib/cmake/cryptopp")
	install(EXPORT ${export_name} DESTINATION "lib/cmake/cryptopp")
endif ()

# Tests
if (BUILD_TESTING)
	install(TARGETS cryptest DESTINATION ${CMAKE_INSTALL_BINDIR})
	install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/TestData DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/cryptopp)
	install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/TestVectors DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/cryptopp)
endif ()

# Documentation
if (BUILD_DOCUMENTATION)
	install(DIRECTORY "${out_source_DOCS_DIR}" DESTINATION ${CMAKE_INSTALL_DOCDIR})
endif ()

# Print a configuration summary. We want CXX and CXXFLAGS, but they are not includd in ALL.
if (NOT CMAKE_VERSION VERSION_LESS 3.0.2)
	if (CRYPTOPP_I386)
		message(STATUS "Platform: i386/i686")
	elseif (CRYPTOPP_AMD64)
		message(STATUS "Platform: x86_64")
	elseif (CRYPTOPP_X32)
		message(STATUS "Platform: x86_64-x32")
	elseif (CRYPTOPP_ARMHF)
		message(STATUS "Platform: armhf")
	elseif (CRYPTOPP_ARM)
		message(STATUS "Platform: arm")
	elseif (CRYPTOPP_AARCH32)
		message(STATUS "Platform: Aarch32")
	elseif (CRYPTOPP_AARCH64)
		message(STATUS "Platform: Aarch64")
	elseif (CRYPTOPP_SPARC)
		message(STATUS "Platform: Sparc")
	elseif (CRYPTOPP_SPARC64)
		message(STATUS "Platform: Sparc64")
	elseif (CRYPTOPP_POWERPC)
		message(STATUS "Platform: PowerPC")
	elseif (CRYPTOPP_POWERPC64)
		message(STATUS "Platform: PowerPC64")
	elseif (CRYPTOPP_MINGW32)
		message(STATUS "Platform: MinGW-32")
	elseif (CRYPTOPP_MINGW32)
		message(STATUS "Platform: MinGW-64")
	endif ()
	if (CRYPTOPP_ARMV7A_NEON)
		message(STATUS "NEON: TRUE")
	endif ()
	if (CRYPTOPP_NATIVE_ARCH)
		message(STATUS "Native arch: TRUE")
	else ()
		message(STATUS "Native arch: FALSE")
	endif ()
	message(STATUS "Compiler: ${CMAKE_CXX_COMPILER}")
	message(STATUS "Flags: ${CMAKE_CXX_FLAGS}")
	message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
endif ()

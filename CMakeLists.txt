# Please ensure your changes or patch meets minimum requirements.
#   The minimum requirements are below, and they are 2.8.5. Please
#   do not check in something for 2.8.12. To test your changes,
#   please set up a Ubuntu 12.04 LTS system. Then, manually install
#   Cmake 2.8.5 from http://cmake.org/Wiki/CMake_Released_Versions.

cmake_minimum_required(VERSION 2.8.5 FATAL_ERROR)

project(cryptopp)

set(cryptopp_VERSION_MAJOR 5)
set(cryptopp_VERSION_MINOR 6)
set(cryptopp_VERSION_PATCH 5)

include(GNUInstallDirs)
include(TestBigEndian)

#============================================================================
# Settable options
#============================================================================

option(BUILD_STATIC "Build static library" ON)
option(BUILD_SHARED "Build shared library" ON)
option(BUILD_TESTING "Build library tests" ON)
option(BUILD_DOCUMENTATION "Use Doxygen to create the HTML based API documentation" OFF)

option(DISABLE_ASM "Disable ASM" OFF)
option(DISABLE_SSSE3 "Disable SSSE3" OFF)
option(DISABLE_AESNI "Disable AES-NI" OFF)
set(CRYPTOPP_DATA_DIR "" CACHE PATH "Crypto++ test data directory")

#============================================================================
# Internal compiler options
#============================================================================

# Stop hiding the damn output...
set(CMAKE_VERBOSE_MAKEFILE on)

# Enable PIC for all targets except 32-bit x86
#if (CMAKE_SYSTEM_PROCESSOR)
#	set (CMAKE_CXX_FLAGS "$CMAKE_CXX_FLAGS -fPIC")
#endif()

# Don't use RPATH's. The resulting binary could fail a security audit.
if (NOT CMAKE_VERSION VERSION_LESS 2.8.12)
  set(CMAKE_MACOSX_RPATH 0)
endif()

set(LIB_VER ${cryptopp_VERSION_MAJOR}${cryptopp_VERSION_MINOR}${cryptopp_VERSION_PATCH})

if(CMAKE_CXX_COMPILER_ID MATCHES "Intel")
	add_definitions(-wd68 -wd186 -wd279 -wd327 -wd161 -wd3180)
endif()

# Endianess
TEST_BIG_ENDIAN(IS_BIG_ENDIAN)
if(IS_BIG_ENDIAN)
	add_definitions(-DIS_BIG_ENDIAN)
endif()

if(DISABLE_ASM)
	add_definitions(-DCRYPTOPP_DISABLE_ASM)
endif()
if(DISABLE_SSSE3)
	add_definitions(-DCRYPTOPP_DISABLE_SSSE3)
endif()
if(DISABLE_AESNI)
	add_definitions(-DCRYPTOPP_DISABLE_AESNI)
endif()
if(NOT CRYPTOPP_DATA_DIR STREQUAL "")
	add_definitions(-DCRYPTOPP_DATA_DIR="${CRYPTOPP_DATA_DIR}")
endif()

if(WINDOWS_STORE OR WINDOWS_PHONE)
	if("${CMAKE_SYSTEM_VERSION}" MATCHES "10\\.0.*")
		SET( CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} /D\"_WIN32_WINNT=0x0A00\"" )
	endif()
	SET( CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} /FI\"winapifamily.h\"" )
endif()

#============================================================================
# Sources & headers
#============================================================================

# Library headers
file(GLOB cryptopp_HEADERS *.h)

# Test sources. You can use the GNUmakefile to generate the list: `make sources`.
file(GLOB cryptopp_SOURCES_TEST bench1.cpp bench2.cpp test.cpp validat1.cpp validat2.cpp validat3.cpp adhoc.cpp datatest.cpp regtest.cpp fipsalgt.cpp dlltest.cpp fipstest.cpp)

# Library sources. You can use the GNUmakefile to generate the list: `make sources`.
file(GLOB cryptopp_SOURCES *.cpp)
list(REMOVE_ITEM cryptopp_SOURCES
		${CMAKE_CURRENT_SOURCE_DIR}/cryptlib.cpp
		${CMAKE_CURRENT_SOURCE_DIR}/cpu.cpp
		${CMAKE_CURRENT_SOURCE_DIR}/pch.cpp
		${CMAKE_CURRENT_SOURCE_DIR}/simple.cpp
		${CMAKE_CURRENT_SOURCE_DIR}/winpipes.cpp
		${CMAKE_CURRENT_SOURCE_DIR}/cryptlib_bds.cpp
		${cryptopp_SOURCES_TEST}
		)
set(cryptopp_SOURCES
		${CMAKE_CURRENT_SOURCE_DIR}/cryptlib.cpp
		${CMAKE_CURRENT_SOURCE_DIR}/cpu.cpp
		${cryptopp_SOURCES}
		)

if(MINGW OR WIN32)
	list(APPEND cryptopp_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/winpipes.cpp)
endif()

if(MSVC AND NOT DISABLE_ASM)
	if(${CMAKE_GENERATOR} MATCHES ".*ARM")
		message(STATUS "Disabling ASM because ARM is specified as target platform.")
	else()
		if(CMAKE_SIZEOF_VOID_P EQUAL 8)
			list(APPEND cryptopp_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/x64dll.asm)
			list(APPEND cryptopp_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/x64masm.asm)
			set_source_files_properties(${CMAKE_CURRENT_SOURCE_DIR}/x64dll.asm PROPERTIES COMPILE_FLAGS "/D_M_X64")
			set_source_files_properties(${CMAKE_CURRENT_SOURCE_DIR}/x64masm.asm PROPERTIES COMPILE_FLAGS "/D_M_X64")
			set_source_files_properties(${CMAKE_CURRENT_SOURCE_DIR}/rdrand.asm PROPERTIES COMPILE_FLAGS "/D_M_X64")
		else()
			set_source_files_properties(${CMAKE_CURRENT_SOURCE_DIR}/x64dll.asm PROPERTIES COMPILE_FLAGS "/D_M_X86 /safeseh")
			set_source_files_properties(${CMAKE_CURRENT_SOURCE_DIR}/x64masm.asm PROPERTIES COMPILE_FLAGS "/D_M_X86 /safeseh")
			set_source_files_properties(${CMAKE_CURRENT_SOURCE_DIR}/rdrand.asm PROPERTIES COMPILE_FLAGS "/D_M_X86 /safeseh")
		endif()
		list(APPEND cryptopp_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/rdrand.asm)
		enable_language(ASM_MASM)
	endif()
endif()

#============================================================================
# Compile targets
#============================================================================

# Set global includes BEFORE adding any targets for legacy CMake versions
if(CMAKE_VERSION VERSION_LESS 2.8.12)
	include_directories("${CMAKE_CURRENT_SOURCE_DIR}")
endif()

if(NOT CMAKE_VERSION VERSION_LESS 2.8.8)
	add_library(cryptopp-object OBJECT ${cryptopp_SOURCES})
endif()

if (BUILD_STATIC)
	if(NOT CMAKE_VERSION VERSION_LESS 2.8.8)
		add_library(cryptopp-static STATIC $<TARGET_OBJECTS:cryptopp-object>)
	else()
		add_library(cryptopp-static STATIC ${cryptopp_SOURCES})
	endif()

	if (NOT CMAKE_VERSION VERSION_LESS 2.8.12)
		target_include_directories(cryptopp-static PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}> $<INSTALL_INTERFACE:include/cryptopp>)
	endif()
endif()

if (BUILD_SHARED)
	if(NOT CMAKE_VERSION VERSION_LESS 2.8.8)
		add_library(cryptopp-shared SHARED $<TARGET_OBJECTS:cryptopp-object>)
	else()
		add_library(cryptopp-shared SHARED ${cryptopp_SOURCES})
	endif()

	if (NOT CMAKE_VERSION VERSION_LESS 2.8.12)
		target_include_directories(cryptopp-shared PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}> $<INSTALL_INTERFACE:include/cryptopp>)
	endif()
endif()

# Set PIC
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
	# Enables -fPIC on all 64-bit platforms
	if(NOT CMAKE_VERSION VERSION_LESS 2.8.9)	# POSITION_INDEPENDENT_CODE support
		set_target_properties(cryptopp-object PROPERTIES POSITION_INDEPENDENT_CODE TRUE)
	elseif(NOT CMAKE_VERSION VERSION_LESS 2.8.8)	# Object library support
		get_target_property(flags_old cryptopp-object COMPILE_FLAGS)
		set_target_properties(cryptopp-object PROPERTIES COMPILE_FLAGS "${flags_old} -fPIC")
	else()
		if (BUILD_STATIC)
			get_target_property(flags_old_static cryptopp-static COMPILE_FLAGS)
			if(NOT flags_old_static)
				set(flags_old_static "")
			endif()
			set_target_properties(cryptopp-static PROPERTIES COMPILE_FLAGS "${flags_old_static} -fPIC")
		endif()
		if (BUILD_SHARED)
			get_target_property(flags_old_shared cryptopp-shared COMPILE_FLAGS)
			if(NOT flags_old_shared)
				set(flags_old_shared "")
			endif()
			set_target_properties(cryptopp-shared PROPERTIES COMPILE_FLAGS "${flags_old_shared} -fPIC")
		endif()
	endif()
endif()

# Set filenames for targets to be "cryptopp"
if(NOT MSVC)
	set(COMPAT_VERSION ${cryptopp_VERSION_MAJOR}.${cryptopp_VERSION_MINOR})

	if (BUILD_STATIC)
		set_target_properties(cryptopp-static
				PROPERTIES
				OUTPUT_NAME cryptopp)
	endif()
	if (BUILD_SHARED)
		set_target_properties(cryptopp-shared
				PROPERTIES
				SOVERSION ${COMPAT_VERSION}
				OUTPUT_NAME cryptopp)
	endif()
endif()

# Targets, compatible with Crypto++ GNUMakefile
if (BUILD_STATIC)
	add_custom_target(static)
	add_dependencies(static cryptopp-static)
endif()
if (BUILD_SHARED)
	add_custom_target(dynamic)
	add_dependencies(dynamic cryptopp-shared)
endif()

#============================================================================
# Third-party libraries
#============================================================================

if(WIN32)
	if (BUILD_STATIC)
		target_link_libraries(cryptopp-static ws2_32)
	endif()
	if (BUILD_SHARED)
		target_link_libraries(cryptopp-shared ws2_32)
	endif()
endif()

# This may need to be expanded to "Solaris"
if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "SunPro")
	if (BUILD_STATIC)
		target_link_libraries(cryptopp-static nsl socket)
	endif()
	if (BUILD_SHARED)
		target_link_libraries(cryptopp-shared nsl socket)
	endif()
endif()

find_package(Threads)
if (BUILD_STATIC)
	target_link_libraries(cryptopp-static ${CMAKE_THREAD_LIBS_INIT})
endif()
if (BUILD_SHARED)
	target_link_libraries(cryptopp-shared ${CMAKE_THREAD_LIBS_INIT})
endif()

#============================================================================
# Tests
#============================================================================

enable_testing()
if(BUILD_TESTING)
	add_executable(cryptest ${cryptopp_SOURCES_TEST})
	target_link_libraries(cryptest cryptopp-static)

	# Setting "cryptest" binary name to "cryptest.exe"
	if(NOT WIN32)
		set_target_properties(cryptest PROPERTIES OUTPUT_NAME cryptest.exe)
	endif()
	if(NOT TARGET cryptest.exe)
		add_custom_target(cryptest.exe)
		add_dependencies(cryptest.exe cryptest)
	endif()

	file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/TestData DESTINATION ${PROJECT_BINARY_DIR})
	file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/TestVectors DESTINATION ${PROJECT_BINARY_DIR})

	add_test(NAME build_cryptest COMMAND "${CMAKE_COMMAND}" --build ${CMAKE_BINARY_DIR} --target cryptest)
	add_test(NAME cryptest COMMAND $<TARGET_FILE:cryptest> v)
	set_tests_properties(cryptest PROPERTIES DEPENDS build_cryptest)
endif()

#============================================================================
# Doxygen documentation
#============================================================================

if(BUILD_DOCUMENTATION)
	find_package(Doxygen REQUIRED)

	set(in_source_DOCS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/html-docs")
	set(out_source_DOCS_DIR "${PROJECT_BINARY_DIR}/html-docs")

	add_custom_target(docs ALL
			COMMAND ${DOXYGEN_EXECUTABLE} Doxyfile -d CRYPTOPP_DOXYGEN_PROCESSING
			WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
			SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile
			)

	if(NOT ${in_source_DOCS_DIR} STREQUAL ${out_source_DOCS_DIR})
		add_custom_command(
				TARGET docs POST_BUILD
				COMMAND ${CMAKE_COMMAND} -E copy_directory "${in_source_DOCS_DIR}" "${out_source_DOCS_DIR}"
				COMMAND ${CMAKE_COMMAND} -E remove_directory "${in_source_DOCS_DIR}"
		)
	endif()
endif()

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
endif()

# Development package
if (BUILD_STATIC)
	install(TARGETS cryptopp-static EXPORT ${export_name} DESTINATION ${CMAKE_INSTALL_LIBDIR})
endif()
install(FILES ${cryptopp_HEADERS} DESTINATION include/cryptopp)

# CMake Package
if(NOT CMAKE_VERSION VERSION_LESS 2.8.8)	# CMakePackageConfigHelpers is supported from 2.8.8
	include(CMakePackageConfigHelpers)
	write_basic_package_version_file("${PROJECT_BINARY_DIR}/cryptopp-config-version.cmake" VERSION ${cryptopp_VERSION_MAJOR}.${cryptopp_VERSION_MINOR}.${cryptopp_VERSION_PATCH} COMPATIBILITY SameMajorVersion)
	install(FILES cryptopp-config.cmake ${PROJECT_BINARY_DIR}/cryptopp-config-version.cmake DESTINATION "lib/cmake/cryptopp")
	install(EXPORT ${export_name} DESTINATION "lib/cmake/cryptopp")
endif()

# Tests
if(BUILD_TESTING)
	install(TARGETS cryptest DESTINATION ${CMAKE_INSTALL_BINDIR})
	install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/TestData DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/cryptopp)
	install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/TestVectors DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/cryptopp)
endif()

# Documentation
if(BUILD_DOCUMENTATION)
	install(DIRECTORY "${out_source_DOCS_DIR}" DESTINATION ${CMAKE_INSTALL_DOCDIR})
endif()

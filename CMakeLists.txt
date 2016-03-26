cmake_minimum_required(VERSION 2.8.7 FATAL_ERROR)

project(cryptopp)
set(cryptopp_VERSION 5.6.3)

include(GNUInstallDirs)
include(TestBigEndian)
include(CheckCXXSymbolExists)

if(POLICY CMP0042)
	cmake_policy(SET CMP0042 NEW)
endif()

#============================================================================
# Settable options
#============================================================================

option(BUILD_TESTING "Build library tests" ON)
option(BUILD_DOCUMENTATION "Use Doxygen to create the HTML based API documentation" OFF)

option(DISABLE_ASM "Disable ASM" OFF)
option(DISABLE_SSSE3 "Disable SSSE3" OFF)
option(DISABLE_AESNI "Disable AES-NI" OFF)
set(CRYPTOPP_DATA_DIR "" CACHE PATH "Crypto++ test data directory")

#============================================================================
# Internal compiler options
#============================================================================

string(REPLACE "." ";" cryptopp_VERSION_LIST ${cryptopp_VERSION})
list(GET cryptopp_VERSION_LIST 0 cryptopp_VERSION_MAJOR)
list(GET cryptopp_VERSION_LIST 1 cryptopp_VERSION_MINOR)
list(GET cryptopp_VERSION_LIST 2 cryptopp_VERSION_PATCH)

math(EXPR BITS "8*${CMAKE_SIZEOF_VOID_P}")

if(CMAKE_CXX_COMPILER_ID MATCHES "Intel")
	add_definitions(-wd68 -wd186 -wd279 -wd327 -wd161 -wd3180)
endif()

# Endianess
test_big_endian(IS_BIG_ENDIAN)
if(IS_BIG_ENDIAN)
	add_definitions(-DIS_BIG_ENDIAN)
endif()

# Position independent code
if(BITS EQUAL 64)
	# Enables -fPIC on all 64-bit platforms
	set(cryptopp_POSITION_INDEPENDENT_CODE TRUE)
else()
	set(cryptopp_POSITION_INDEPENDENT_CODE FALSE)
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

#============================================================================
# Sources & headers
#============================================================================

# Library headers
file(GLOB cryptopp_HEADERS *.h)

# Test sources
file(GLOB cryptopp_SOURCES_TEST bench.cpp bench2.cpp test.cpp validat1.cpp validat2.cpp validat3.cpp adhoc.cpp datatest.cpp regtest.cpp fipsalgt.cpp dlltest.cpp fipstest.cpp)

# Library sources
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

if(WIN32)
	list(APPEND cryptopp_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/winpipes.cpp)
endif()

if(MSVC AND NOT DISABLE_ASM)
	enable_language(ASM_MASM)
	if(BITS EQUAL 32)
		set(CMAKE_ASM_MASM_FLAGS "${CMAKE_ASM_MASM_FLAGS} /nologo /D_M_X86 /W3 /Cx /Zi /safeseh")
	else()
		set(CMAKE_ASM_MASM_FLAGS "${CMAKE_ASM_MASM_FLAGS} /nologo /D_M_X64 /W3 /Cx /Zi")
		list(APPEND cryptopp_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/x64dll.asm)
		list(APPEND cryptopp_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/x64masm.asm)
	endif()
	list(APPEND cryptopp_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/rdrand.asm)
endif()

#============================================================================
# Compile targets
#============================================================================
if(${CMAKE_VERSION} VERSION_GREATER 2.8.8)
	include("cmake/cryptopp-compile-targets-2.8.8.cmake")
else()
	include("cmake/cryptopp-compile-targets.cmake")
endif()

if(NOT MSVC)
	set(COMPAT_VERSION ${cryptopp_VERSION_MAJOR}.${cryptopp_VERSION_MINOR})

	set_target_properties(cryptopp-static
			PROPERTIES
			OUTPUT_NAME cryptopp)
	set_target_properties(cryptopp-shared
			PROPERTIES
			SOVERSION ${COMPAT_VERSION}
			OUTPUT_NAME cryptopp)
endif()

#============================================================================
# Third-party libraries
#============================================================================
if(WIN32)
	target_link_libraries(cryptopp-static ws2_32)
	target_link_libraries(cryptopp-shared ws2_32)
endif()

find_package(Threads)
target_link_libraries(cryptopp-static ${CMAKE_THREAD_LIBS_INIT})
target_link_libraries(cryptopp-shared ${CMAKE_THREAD_LIBS_INIT})

#============================================================================
# Tests
#============================================================================
enable_testing()
if(BUILD_TESTING)
	add_executable(cryptest ${cryptopp_SOURCES_TEST})
	target_link_libraries(cryptest cryptopp-static)

	file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/TestData DESTINATION ${PROJECT_BINARY_DIR})
	file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/TestVectors DESTINATION ${PROJECT_BINARY_DIR})

	add_test(NAME cryptest COMMAND $<TARGET_FILE:cryptest> v)
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
install(TARGETS cryptopp-shared EXPORT ${export_name} DESTINATION ${CMAKE_INSTALL_LIBDIR})

# Development package
install(TARGETS cryptopp-static EXPORT ${export_name} DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(FILES ${cryptopp_HEADERS} DESTINATION include/cryptopp)

# CMake Package
set(CVF_VERSION "${cryptopp_VERSION}")
configure_file(cmake/cryptopp-config-version.in ${PROJECT_BINARY_DIR}/cryptopp-config-version.cmake)
install(FILES cmake/cryptopp-config.cmake ${PROJECT_BINARY_DIR}/cryptopp-config-version.cmake DESTINATION "lib/cmake/cryptopp")
install(EXPORT ${export_name} DESTINATION "lib/cmake/cryptopp")

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
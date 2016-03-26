add_library(cryptopp-object OBJECT ${cryptopp_SOURCES})

set_target_properties(cryptopp-object PROPERTIES POSITION_INDEPENDENT_CODE ${cryptopp_POSITION_INDEPENDENT_CODE})

add_library(cryptopp-static STATIC $<TARGET_OBJECTS:cryptopp-object>)
add_library(cryptopp-shared SHARED $<TARGET_OBJECTS:cryptopp-object>)

target_include_directories(cryptopp-shared PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}> $<INSTALL_INTERFACE:include/cryptopp>)
target_include_directories(cryptopp-static PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}> $<INSTALL_INTERFACE:include/cryptopp>)

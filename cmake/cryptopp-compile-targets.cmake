add_library(cryptopp-static STATIC ${cryptopp_SOURCES})
add_library(cryptopp-shared SHARED ${cryptopp_SOURCES})

set_target_properties(cryptopp-static PROPERTIES POSITION_INDEPENDENT_CODE ${cryptopp_POSITION_INDEPENDENT_CODE})
set_target_properties(cryptopp-shared PROPERTIES POSITION_INDEPENDENT_CODE ${cryptopp_POSITION_INDEPENDENT_CODE})

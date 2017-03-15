// cryptest-coverity.cpp - Coverity modeling file.
//                         Written and placed in public domain by Jeffrey Walton and Uri Blumenthal.
//
// For more information see http://cryptopp.com/wiki/Coverity_Scan.
//
// Also see https://scan.coverity.com/tune#what-is-model

///////////////////////////////////////////////////////////////////

void special_abort(const char* msg) {
	__coverity_panic__();
}

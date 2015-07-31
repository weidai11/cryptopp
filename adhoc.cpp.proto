#include "cryptlib.h"
#include "stdcpp.h"
#include "misc.h"

USING_NAMESPACE(CryptoPP)

#if GCC_DIAGNOSTIC_AWARE
# pragma GCC diagnostic push
# pragma GCC diagnostic ignored "-Wunused-variable"
# pragma GCC diagnostic ignored "-Wunused-parameter"
#endif

extern int (*AdhocTest)(int argc, char *argv[]);

int MyAdhocTest(int argc, char *argv[])
{
	return 0;
}

static int s_i = (AdhocTest = &MyAdhocTest, 0);

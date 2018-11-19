#include <altivec.h>

// This follows ppc_simd.h. XLC compilers for POWER7 use vec_xlw4 and vec_xstw4.
// XLC compilers for POWER8 and above use vec_xl and vec_xst. The way to tell
// the difference is, POWER7 XLC compilers are version 12.x and earlier.
// The open question is, how to handle early Clang compilers for POWER7.
// We know the latest Clang compilers support vec_xl and vec_xst.

#if defined(__xlc__) && (__xlc__ < 0x0d00)
# define __old_xlc__ 1
#endif

#if defined(__xlC__) && (__xlC__ < 0x0d00)
# define __old_xlC__ 1
#endif

int main(int argc, char* argv[])
{
	__vector unsigned char x;
	unsigned char res[16];

#if defined(__old_xlc__) || defined(__old_xlC__)
    x=vec_xlw4(0, (unsigned char*)argv[0]);
	x=vec_add(x,x);
	vec_xstw4(x, 0, res);
#elif defined(__xlc__) || defined(__xlC__) || defined(__clang__)
	x=vec_xl(0, (unsigned char*)argv[0]);
	x=vec_add(x,x);
	vec_xst(x, 0, res);
#elif defined(__GNUC__)
	x=vec_vsx_ld(0, (unsigned char*)argv[0]);
	x=vec_add(x,x);
	vec_vsx_st(x, 0, res);
#else
	int XXX[-1];
#endif
	return 0;
}

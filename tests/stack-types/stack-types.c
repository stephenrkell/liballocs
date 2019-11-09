#include <stdio.h>
#include "liballocs.h"

extern struct uniqtype __uniqtype__int;
extern struct uniqtype __uniqtype__long_int;

int f(int arg1, int arg2, int arg3)
{
	struct { long q1; long q2; long q3; } blah = { (long) &arg1, (long) &arg2, (long) &arg3 };
	/* Interestingly, with gcc 8.3, arg2 has no location information
	 * in the DWARF, despite being address-taken here. Unsurprisingly,
	 * that makes this test case fail. Comment out for now, but this
	 * is a great example of why the compiler can't currently be
	 * trusted. If we had marked __liballocs_get_alloc_type as pure,
	 * then I could understand the compiler's behaviour, but we
	 * haven't. */
	// struct uniqtype *u1 = __liballocs_get_inner_type(&arg2, 0);
	struct uniqtype *u2 = __liballocs_get_inner_type(&blah.q2, 0);
	// assert(u1 == &__uniqtype__int);
	assert(u2 == &__uniqtype__long_int);
	return arg2 + 1;
}


int main(void)
{
	return f(42, 42, 42) - 43;
}

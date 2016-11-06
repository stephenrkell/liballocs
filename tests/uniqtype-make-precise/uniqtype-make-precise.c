#include "uniqtype.h"

struct xyzzy
{
	int z;
} x;
extern struct uniqtype __uniqtype__xyzzy __attribute__((weak));

/* imprecise uniqtype for "__ARR0_xyzzy" */
const char *__uniqtype____ARR0_xyzzy_subobj_names[]  __attribute__((weak,
section (".data.__uniqtype____ARR0_xyzzy, \"awG\", @progbits, __uniqtype____ARR0_xyzzy, comdat#")))= { (void*)0 };
struct uniqtype __uniqtype____ARR0_xyzzy
__attribute__((section (".data.__uniqtype____ARR0_xyzzy, \"awG\", @progbits, __uniqtype____ARR0_xyzzy, comdat#"))) = {
	{ 0, 0, 0 },
	UNIQTYPE_POS_MAXOFF_UNBOUNDED /* pos_maxoff */,
	{ array: { 1, UNIQTYPE_ARRAY_LENGTH_UNBOUNDED } },
	/* make_precise */ __liballocs_make_array_precise_with_memory_bounds, /* related */ {
		{ { t: { &__uniqtype__xyzzy } } }
	}
};

int main(void)
{
	/* Bare-bones test of the make-precise thing. 
	 * We ask the function to make a precise version of itself
	 * for a 1-element array. */
	struct uniqtype *precise = __uniqtype____ARR0_xyzzy.make_precise(
		&__uniqtype____ARR0_xyzzy, NULL, 0,
		&x, &x, sizeof x, NULL, NULL);
	
	printf("We got back: %s\n", UNIQTYPE_NAME(precise));
	
	/* Now call it again: we should get the same pointer, not another
	 * copy of the uniqtype. */
	struct uniqtype *precise2 = __uniqtype____ARR0_xyzzy.make_precise(
		&__uniqtype____ARR0_xyzzy, NULL, 0,
		&x, &x, sizeof x, NULL, NULL);
	
	assert(precise == precise2);
	
	return 0;
}

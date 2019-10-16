#include <stdlib.h>
#include "liballocs.h"
#include "uniqtype.h"

struct xyzzy
{
	int z;
} x;
extern struct uniqtype __uniqtype__xyzzy __attribute__((weak));

int main(void)
{
	/* Bare-bones test of the make-precise thing.
	 * We ask the function to make a precise version of itself
	 * for a 1-element array. */
	struct xyzzy *z = malloc(sizeof (struct xyzzy));
	struct uniqtype *imprecise = __liballocs_get_alloc_type(z);
	assert(imprecise->make_precise);
			
	struct uniqtype *precise = imprecise->make_precise(
		imprecise, NULL, 0,
		&x, &x, sizeof x, NULL, NULL);
	printf("We got back: %s\n", UNIQTYPE_NAME(precise));
	
	/* Now call it again: we should get the same pointer, not another
	 * copy of the uniqtype. */
	struct uniqtype *precise2 = imprecise->make_precise(
		imprecise, NULL, 0,
		&x, &x, sizeof x, NULL, NULL);
	
	assert(precise == precise2);
	
	return 0;
}

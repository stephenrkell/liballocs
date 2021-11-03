#include <stdio.h>
#include "liballocs.h"

extern void x1;
extern void x2;
extern void x3;

int main(void)
{
	typedef long int long_int; // this used to cause us trouble
	long_int i = 0l;

	assert(alloc_get_type(&x1));
	assert(alloc_get_type(&x2));
	assert(alloc_get_type(&x3));

	/* The following reflect our somewhat arbitrary choices around
	 * type identity. We erase the directory name, so the same header
	 * name, even if in different dirs, can yield the identity-equal
	 * type, whereas if we symlink a header under a new name, it can
	 * generate identity-distinct types even for identical definitions. */

	// assert that x1 and x2 have same type (both 'header.h', different paths)
        assert(alloc_get_type(&x1) == alloc_get_type(&x2));
	// assert that x1 and x2 have distinct type ('header.h' vs 'sameheader.h')
        assert(alloc_get_type(&x2) != alloc_get_type(&x3));

	return (int) i;
}

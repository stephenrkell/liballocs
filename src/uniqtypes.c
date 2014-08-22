#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "liballocs.h"

void __liballocs_uniqtypes_dummy(void) __attribute__((optimize("O0")));
void __liballocs_uniqtypes_dummy(void)
{
	/* NO! compiler can optimise past this even at -O0 */
	// assert(0);
	fprintf(stderr, "%p %p %p %p\n", 
		&__uniqtype__void,
		&__uniqtype__signed_char,
		&__uniqtype__unsigned_char,
		&__uniqtype__int);
}

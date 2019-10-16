#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "liballocs.h"

/* Why does this file exist?
 * We never link it into a _preload.so because
 * preloads can violate the uniqueness of global symbols.
 * We do link it into clients who link -allocs, though.
 * In short, it's a hacky way to create a bunch of uniqtypes
 * that we don't dynamically generate. We probably should
 * simply dynamically generate them all in liballocs.c. I've now
 * removed the one that we dynamically generate. FIXME:
 * dynamically generate the rest, then remove this file. */

double __liballocs_blah;
extern struct uniqtype __uniqtype____FUN_FROM___FUN_TO_unsigned_long_int;
unsigned long __liballocs_uniqtypes_dummy() __attribute__((optimize("O0")));
unsigned long __liballocs_uniqtypes_dummy()
{
	/* NO! compiler can optimise past this even at -O0 */
	// assert(0);
	fprintf(stderr, "%p %p %p %p %p %p %p %p\n", 
		&__uniqtype__int,
		&__uniqtype__unsigned_int,
		&/*__liballocs_uniqtype_of_typeless_functions*/ __uniqtype____FUN_FROM___FUN_TO_unsigned_long_int,
		&__uniqtype__short_int,
		&__uniqtype__short_unsigned_int,
		&__uniqtype__float,
		&__uniqtype__double,
		&__uniqtype____PTR_void
	);
	return 42ul;
}

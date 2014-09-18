#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "liballocs.h"

double __liballocs_blah;
extern struct uniqtype __uniqtype____FUN_FROM___FUN_TO_unsigned_long_int;
unsigned long __liballocs_uniqtypes_dummy() __attribute__((optimize("O0")));
unsigned long __liballocs_uniqtypes_dummy()
{
	/* NO! compiler can optimise past this even at -O0 */
	// assert(0);
	fprintf(stderr, "%p %p %p %p %p %p %p %p %p %p %p %p %p %p\n", 
		&__uniqtype__void,
		&__uniqtype__signed_char,
		&__uniqtype__unsigned_char,
		&__uniqtype__int,
		&__uniqtype__unsigned_int,
		&/*__liballocs_uniqtype_of_typeless_functions*/ __uniqtype____FUN_FROM___FUN_TO_unsigned_long_int,
		&__uniqtype__long_int,
		&__uniqtype__unsigned_long_int,
		&__uniqtype__short_int,
		&__uniqtype__short_unsigned_int,
		&__uniqtype__float,
		&__uniqtype__double,
		&__uniqtype____PTR_void,
		&__uniqtype____PTR_signed_char
	);
	return 42ul;
}

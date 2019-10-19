#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <liballocs.h>

extern struct uniqtype __uniqtype__short_unsigned_int;

/* Here we test the __liballocs_add_type_to_block call and related helpers.
 * This is a convenience for code like that in bzip2, which uses C's
 * "effective type" rules' allowance for a type-changing update to memory.
 * E.g. we can first use some memory as an int32_t array, and then re-use it
 * as an array of twice as many int16_t simply by writing int16_t values
 * into it.
 *
 * Code doing that defeats our tracking of the allocation type, so
 * as a workaround, we provide a manual helper __liballocs_add_type_to_block
 * (e.g. we patch bzip2 to make a call to this... sad times).
 *
 * This help replaces the malloc chunk's recorded type with a union
 * of the old type and the given type. We go through the type-update
 * manually to check that the set_type and get_or_create_union_type
 * helpers work, and then go around again using the top-level
 * add-type-to-block helper and check the outcome is the same. */

int main(void)
{
	int *p = malloc(2 * sizeof(int));
	assert(p);
	struct uniqtype *old_type = __liballocs_get_alloc_type(p);
	assert(old_type);
	if (old_type->make_precise) old_type = old_type->make_precise(old_type,
		NULL, 0, p, p, __liballocs_get_alloc_size(p), __builtin_return_address(0), NULL);
	assert(old_type);
	short *sp = realloc(p, 4 * sizeof(short));
	struct uniqtype *new_type = __liballocs_get_alloc_type(p);
	assert(new_type);
	if (new_type->make_precise) new_type = new_type->make_precise(new_type,
		NULL, 0, sp, sp, __liballocs_get_alloc_size(sp), __builtin_return_address(0), NULL);
	assert(new_type);
	struct uniqtype *union_type = __liballocs_get_or_create_union_type(2,
		old_type,
		new_type
	);
	struct allocator *a = __liballocs_leaf_allocator_for(sp, NULL);
	liballocs_err_t err = a->set_type(/*a, */ sp, union_type);
	assert(!err);
	struct uniqtype *got_t = __liballocs_get_alloc_type(sp);
	assert(got_t == union_type);
	printf("The type is now: %s\n", NAME_FOR_UNIQTYPE(got_t));

	/* Now do the same again but with the "add_type_to_block" convenience. */
	int *p2 = malloc(2 * sizeof(int));
	int ret = __liballocs_add_type_to_block(p2, &__uniqtype__short_int);
	struct uniqtype *got_t2 = __liballocs_get_alloc_type(p2);
	assert(got_t2 == union_type);
	printf("And again: the type is now: %s\n", NAME_FOR_UNIQTYPE(got_t2));

	return 0;
}

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <liballocs.h>

int main(void)
{
	int *p = malloc(2 * sizeof(int));
	assert(p);
	struct uniqtype *old_type = __liballocs_get_alloc_type(p);
	assert(old_type);
	if (old_type->make_precise) old_type = old_type->make_precise(old_type,
		NULL, 0, p, p, 2 * sizeof (int), __builtin_return_address(0), NULL);
	assert(old_type);
	short *sp = realloc(p, 4 * sizeof(short));
	struct uniqtype *new_type = __liballocs_get_alloc_type(p);
	assert(new_type);
	if (new_type->make_precise) new_type = new_type->make_precise(new_type,
		NULL, 0, sp, sp, 4 * sizeof (short), __builtin_return_address(0), NULL);
	assert(new_type);
	struct uniqtype *union_type = __liballocs_get_or_create_union_type(2,
		old_type,
		new_type
	);
	struct allocator *a = __liballocs_leaf_allocator_for(sp, NULL, NULL);
	liballocs_err_t err = a->set_type(/*a, */ sp, union_type);
	assert(!err);
	struct uniqtype *got_t = __liballocs_get_alloc_type(sp);
	assert(got_t == union_type);
	printf("The type is now: %s\n", NAME_FOR_UNIQTYPE(got_t));
	return 0;
}

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <liballocs.h>

struct blah
{
	int x;
	float y;
	char z[1];
};

struct baz
{
	void *a;
	struct blah b[1];
};

int main(void)
{
	void *b = calloc(1, offsetof(struct blah, z) + 10);
	
	// assert that the alloc is a blah
	struct uniqtype *got_type = __liballocs_get_alloc_type(b);
	struct uniqtype *blah_type = dlsym(RTLD_NEXT, "__uniqtype__blah");
	assert(blah_type);
	assert(got_type);
	assert(got_type == blah_type);
	
	printf("It says: %f\n", ((struct blah *) b)->y);
	
	void *bz = calloc(1, offsetof(struct baz, b) + 20 * sizeof (struct blah));
	
	// assert that the alloc is the composite
	struct uniqtype *got_comp_type = __liballocs_get_alloc_type(bz);
	struct uniqtype *baz_type = dlsym(RTLD_NEXT, "__uniqtype__baz");
	assert(baz_type);
	assert(got_comp_type);
	assert(got_comp_type->un.info.kind == COMPOSITE);
	assert(got_comp_type->related[0].un.memb.ptr == baz_type);
	assert(got_comp_type->related[1].un.memb.ptr->un.array.is_array);
	assert(got_comp_type->related[1].un.memb.ptr->related[0].un.memb.ptr == blah_type);

	return 0;
}

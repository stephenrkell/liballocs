#define _GNU_SOURCE
#include <alloca.h>
#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <liballocs.h>

extern __thread void *__current_allocsite __attribute__((weak));

int main(void)
{
	void *o = alloca(42 * sizeof (int));
	printf("alloca'd chunk at %p\n", o);
	struct big_allocation *b;
	struct allocator *a = __liballocs_leaf_allocator_for(o, &b);
	assert(a == &__alloca_allocator);
	struct uniqtype *got_type = __liballocs_get_alloc_type(o);
	struct uniqtype *int_type = dlsym(RTLD_DEFAULT, "__uniqtype__int");
	assert(int_type);
	assert(got_type);
	assert(UNIQTYPE_IS_ARRAY_TYPE(got_type));
	assert(UNIQTYPE_ARRAY_ELEMENT_TYPE(got_type) == int_type);
	
	void *b = alloca(69105);
	printf("alloca'd chunk at %p\n", b);
	// can we still get the type of o (not b)?
	struct uniqtype *got_type_again = __liballocs_get_alloc_type(o);
	assert(got_type_again);
	assert(got_type_again == got_type);
	return 0;
}


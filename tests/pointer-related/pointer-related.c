#define _GNU_SOURCE
#include <stdio.h>
#include <stddef.h>
#include <assert.h>
#include <link.h>
#include <dlfcn.h>
#include "allocs.h"

int an_int = 42;
int *a_ptr = &an_int;
int **a_ptr_ptr = &a_ptr;

static size_t uniqtype_symbol_size(struct uniqtype *u)
{
	Dl_info info;
	const ElfW(Sym) *sym = NULL;
	int ret = dladdr1((char *) u + 1, &info, (void **) &sym, RTLD_DL_SYMENT);
	assert(ret != 0);
	assert(sym);
	assert(info.dli_saddr == u);
	return sym->st_size;
}

int main(void)
{
	struct uniqtype *int_t = dlsym(RTLD_DEFAULT, "__uniqtype__int$$32");
	struct uniqtype *p_t = dlsym(RTLD_DEFAULT, "__uniqtype____PTR_int$$32");
	struct uniqtype *pp_t = dlsym(RTLD_DEFAULT, "__uniqtype____PTR___PTR_int$$32");
	assert(int_t && p_t && pp_t);

	size_t one_related = offsetof(struct uniqtype, related)
		+ 1 * sizeof (struct uniqtype_rel_info);
	size_t two_related = offsetof(struct uniqtype, related)
		+ 2 * sizeof (struct uniqtype_rel_info);

	assert(UNIQTYPE_IS_POINTER_TYPE(p_t));
	assert(p_t->un.address.indir_level == 1);
	assert(UNIQTYPE_POINTEE_TYPE(p_t) == int_t);
	assert(UNIQTYPE_ULTIMATE_POINTEE_TYPE(p_t) == int_t);
	assert(uniqtype_symbol_size(p_t) == one_related);

	assert(UNIQTYPE_IS_POINTER_TYPE(pp_t));
	assert(pp_t->un.address.indir_level == 2);
	assert(UNIQTYPE_POINTEE_TYPE(pp_t) == p_t);
	assert(UNIQTYPE_ULTIMATE_POINTEE_TYPE(pp_t) == int_t);
	assert(uniqtype_symbol_size(pp_t) == two_related);

	printf("%s is %zu bytes, %s is %zu bytes\n",
		UNIQTYPE_NAME(p_t), uniqtype_symbol_size(p_t),
		UNIQTYPE_NAME(pp_t), uniqtype_symbol_size(pp_t));
	return 0;
}

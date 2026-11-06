#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>
#include <elf.h>
#include <link.h>
#include <dlfcn.h>
#include "allocs.h"
#include "allocmeta.h"

int an_int = 42;
int *a_ptr = &an_int;
struct two_ints { int first; int second; } a_pair = { 1, 2 };

static struct uniqtype *int_t;
static _Bool saw_int_t;
static int note_type(struct uniqtype *t, void *arg)
{
	++*(unsigned *) arg;
	if (t == int_t) saw_int_t = 1;
	return 0;
}

int main(void)
{
	/* Names come via dladdr() */
	struct uniqtype *main_t = __liballocs_get_alloc_type(main);
	assert(main_t);
	assert(__liballocs_uniqtype_symbol_name(main_t));

	void *file_metadata = __liballocs_get_specific_by_allocator(main,
		&__static_file_allocator, NULL);
	assert(file_metadata);
	struct allocs_file_metadata *meta = file_metadata;
	struct link_map *l = meta->meta_obj_handle;
	assert(l);

	/* Only the GNU-style hash table should be present. */
	_Bool have_gnu_hash = 0, have_sysv_hash = 0;
	for (ElfW(Dyn) *d = l->l_ld; d->d_tag != DT_NULL; ++d)
	{
		if (d->d_tag == DT_GNU_HASH) have_gnu_hash = 1;
		if (d->d_tag == DT_HASH) have_sysv_hash = 1;
	}
	assert(have_gnu_hash);
	assert(!have_sysv_hash);

	int_t = dlsym(l, "__uniqtype__int$$32");
	assert(int_t);
	assert(0 == strcmp(UNIQTYPE_NAME(int_t), "int$$32"));
	struct uniqtype *ptr_int_t = dlsym(l, "__uniqtype____PTR_int$$32");
	assert(ptr_int_t);
	assert(UNIQTYPE_POINTEE_TYPE(ptr_int_t) == int_t);

	/* Iterating types has to count dynsyms without a SysV hash table.
	 * (The preload defines this; the link-time stubs don't, so look it up.) */
	int (*iterate_types)(void *, int (*)(struct uniqtype *, void *), void *)
	 = dlsym(RTLD_DEFAULT, "__liballocs_iterate_types");
	assert(iterate_types);
	unsigned ntypes = 0;
	iterate_types(l, note_type, &ntypes);
	assert(ntypes > 0);
	assert(saw_int_t);

	/* Subobject names are reached from the composite's related[] entry,
	 * not by symbol, so no *_subobj_names array should be exported. */
	struct uniqtype *pair_t = dlsym(l, "__uniqtype__two_ints");
	assert(pair_t);
	assert(UNIQTYPE_IS_COMPOSITE_TYPE(pair_t));
	const char **names = UNIQTYPE_COMPOSITE_SUBOBJ_NAMES(pair_t);
	assert(names && names[0] && names[1] && !names[2]);
	assert(0 == strcmp(names[0], "first"));
	assert(0 == strcmp(names[1], "second"));

	/* No static symbol table on disk, and no exported *_subobj_names. */
	assert(l->l_name && l->l_name[0]);
	int fd = open(l->l_name, O_RDONLY);
	assert(fd != -1);
	ElfW(Ehdr) ehdr;
	assert(read(fd, &ehdr, sizeof ehdr) == sizeof ehdr);
	assert(0 == memcmp(ehdr.e_ident, ELFMAG, SELFMAG));
	size_t shdrs_sz = ehdr.e_shnum * sizeof (ElfW(Shdr));
	ElfW(Shdr) *shdrs = malloc(shdrs_sz);
	assert(shdrs);
	assert(lseek(fd, ehdr.e_shoff, SEEK_SET) != -1);
	assert(read(fd, shdrs, shdrs_sz) == (ssize_t) shdrs_sz);
	for (unsigned i = 0; i < ehdr.e_shnum; ++i)
	{
		assert(shdrs[i].sh_type != SHT_SYMTAB);
		if (shdrs[i].sh_type != SHT_DYNSYM) continue;
		ElfW(Shdr) *strsh = &shdrs[shdrs[i].sh_link];
		char *dynstr = malloc(strsh->sh_size);
		ElfW(Sym) *dynsym = malloc(shdrs[i].sh_size);
		assert(dynstr && dynsym);
		assert(lseek(fd, strsh->sh_offset, SEEK_SET) != -1);
		assert(read(fd, dynstr, strsh->sh_size) == (ssize_t) strsh->sh_size);
		assert(lseek(fd, shdrs[i].sh_offset, SEEK_SET) != -1);
		assert(read(fd, dynsym, shdrs[i].sh_size) == (ssize_t) shdrs[i].sh_size);
		for (unsigned j = 0; j < shdrs[i].sh_size / sizeof (ElfW(Sym)); ++j)
		{
			const char *name = dynstr + dynsym[j].st_name;
			size_t len = strlen(name);
			const char suffix[] = "_subobj_names";
			assert(len < sizeof suffix - 1
				|| 0 != strcmp(name + len - (sizeof suffix - 1), suffix));
		}
		free(dynstr);
		free(dynsym);
	}
	free(shdrs);
	close(fd);
	return 0;
}

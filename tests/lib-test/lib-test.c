#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <elf.h>

/* FIXME: giant hack! see allocators/elf-file.c.
 * This is our way of ensuring that uniqtypes used by the ELF file
 * allocator are always available when we run the tests on it.
 * However, it would be better if we could write this into the
 * liballocs source somehow. As we know, preloading uniqtypes breaks
 * global uniqueness. We could generate them from the UNDs in
 * liballocs_preload.so and put them in liballocs_static.a, but
 * that would not work when just preloading liballocs into a
 * binary that was not linked -lallocs. Probably we need to use
 * allocsld. The rule is that any uniqtypes required by liballocs
 * that are NOT present in the executable should be somehow injected.
 * Can we use the dlbind library as the place to put them? No
 * because liballocs generates that.
 */
Elf64_Ehdr ehdr;
Elf64_Shdr shdr[1];
Elf64_Phdr phdr[1];
Elf64_Nhdr nhdr[1];
Elf64_Sym sym[1];
Elf64_Rela rela[1];
Elf64_Rel rel[1];
Elf64_Dyn dyn[1];
void (*fp)(void);

int main(void)
{
	/* The liballocs source code includes some unit tests.
	 * These are run as constructors from liballocs_test.so,
	 * so dlopening that will run them. */
	assert(getenv("LIBALLOCS_BUILD"));
	char *path = getenv("LIBALLOCS_BUILD");
	void *handle = dlopen(path, RTLD_NOW);
	assert(handle);
	printf("Successfully constructed %s\n", path);
	return 0;
}

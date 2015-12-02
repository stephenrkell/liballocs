#define _GNU_SOURCE
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include "relf.h"

extern char **environ;

int main(int argc, const char **argv)
{
	fprintf(stderr, "A stackptr is %p\n", &argc);
	fflush(stderr);
	// sleep(10); /* DEBUG HACK */
	
	ElfW(auxv_t) *found = get_auxv((const char **) environ, &argc);
	assert(found);
	fprintf(stderr, "Think we found the auxv at %p; first words are (%p, %p)\n", 
		found, ((void**) found)[0], ((void **) found)[1]);
	
	ElfW(auxv_t) *found_phdr = auxv_lookup(found, AT_PHDR);
	assert(found_phdr);
	ElfW(auxv_t) *found_phnum = auxv_lookup(found, AT_PHNUM);
	assert(found_phnum);
	ElfW(auxv_t) *found_phent = auxv_lookup(found, AT_PHENT);
	assert(found_phent);
	
	fprintf(stderr, "Found %d phdrs of size %ld at %p\n", 
		(int) found_phnum->a_un.a_val, 
		(long int) found_phent->a_un.a_val, 
		(void*) found_phdr->a_un.a_val);
	
	return 0;
}

#include <stdlib.h>
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

void *myalloc_myalloc_addr;
void *myalloc(size_t sz)
{
	printf("myalloc: I think my addr is %p\n", myalloc);
	myalloc_myalloc_addr = myalloc;
	return malloc(sz);
}

/* This is testing that self-references within an allocation function
 * are *not* diverted into the wrapper, even when unbinding.
 * FIXME: is this definitely the behaviour that we want?
 */

int main(void)
{
	void *myalloc_addr = dlsym(NULL, "myalloc");
	assert(myalloc_addr);
	void *p = myalloc(42);
	strcpy((char*) p, "Hello!");
	printf("main: I think myalloc's addr is %p\n", myalloc_addr);
	assert(myalloc_myalloc_addr == myalloc_addr);
	
	printf("%s\n", (char*) p);
	
	return 0;
}

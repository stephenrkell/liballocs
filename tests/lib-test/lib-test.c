#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <assert.h>

int main(void)
{
	/* The liballocs source code includes some unit tests.
	 * These are run as constructors from liballocs_test.so,
	 * so dlopening that will run them. */
	void *handle = dlopen("../../src/liballocs_test.so", RTLD_NOW);
	assert(handle);
	return 0;
}

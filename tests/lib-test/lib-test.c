#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

int main(void)
{
	/* The liballocs source code includes some unit tests.
	 * These are run as constructors from liballocs_test.so,
	 * so dlopening that will run them. */
	char *path = NULL;
	assert(getenv("LIBALLOCS_BUILD"));
	int ret = asprintf(&path, "%s/%s", getenv("LIBALLOCS_BUILD"), "/liballocs_test.so");
	assert(ret > 0);
	void *handle = dlopen(path, RTLD_NOW);
	assert(handle);
	free(path);
	return 0;
}

#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <assert.h>

int main(void)
{
	void *handle = dlopen("../../src/liballocs_test.so", RTLD_NOW);
	assert(handle);
	return 0;
}

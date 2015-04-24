#define _GNU_SOURCE
#include <alloca.h>
#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <liballocs.h>

extern __thread void *__current_allocsite __attribute__((weak));

int main(void)
{
	int *a = alloca(42 * sizeof (int));
	a[41] = 0;
	printf("Saw address %p holding %d\n", &a[41], a[41]);
	return a[41];
}


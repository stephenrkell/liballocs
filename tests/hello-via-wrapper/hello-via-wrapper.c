#include <stdlib.h>
#include <stdio.h>

/* This is a temporary test case for the transition from
 * allocscc/allocscompilerwrapper.py to the new toolsub-based
 * approach of minimalist wrapping + linker plugin. */

int main(void)
{
	void *m = malloc(42);
	printf("Hello, via wrapper! Got %p\n", m);
	free(m);
	return 0;
}

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>

struct blah
{
	int x;
	float y;
	char z[1];
};

struct baz
{
	void *a;
	struct blah b[1];
};

int main(void)
{

	void *b = calloc(1, offsetof(struct blah, z) + 10);
	
	// assert that the alloc is a blah
	printf("It says: %f\n", ((struct blah *) b)->y);
	






	void *bz = calloc(1, offsetof(struct baz, b) + 20 * sizeof (struct blah));
	
	return 0;
}

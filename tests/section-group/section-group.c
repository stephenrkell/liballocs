#include <assert.h>
#include <stdlib.h>
#include <stdio.h>

void *l1(void);
void *l2(void);

int main(void)
{
	void *addr1 = l1();
	void *addr2 = l2();
	assert(addr1 == addr2);
	assert(addr1 != NULL);
	assert(addr2 != NULL);
	printf("Section groups / COMDAT seem to be working:\n"
		"got %p for both l1.so and l2.so's __uniqtype__signed_int\n", addr1);
	return 0;
}

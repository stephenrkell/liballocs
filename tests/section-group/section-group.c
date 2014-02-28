#include <assert.h>
#include <stdlib.h>
#include <stdio.h>

void *l1(void);
void *l2(void);

int main(void)
{
	/* Here we're testing two things: 
	 * 
	 * - that section groups within a dynamic (type)object have worked as expected,
	 *
	 *    meaning that multiple definitions of the same type have been collapsed;
	 * 
	 * - that global linkage *across dynamic objects* have worked as expected, 
	 * 
	 *    meaning that a single global definition of the same type is used across
	 *    all referencing objects. 
	 */
	void *addr1 = l1();
	void *addr2 = l2();
	assert(addr1 == addr2);
	assert(addr1 != NULL);
	assert(addr2 != NULL);
	printf("Link-time uniquing seems to be working:\n"
		"got %p for both l1.so and l2.so's __uniqtype__int$32\n", addr1);
	return 0;
}

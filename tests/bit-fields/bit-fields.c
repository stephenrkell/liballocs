#define _GNU_SOURCE
#include <stdio.h>
#include <liballocs.h>

struct bits
{
	unsigned long x:62;
	int y;
	char z;
	signed awkward:7;
};

int main(void)
{
	struct bits b = { 1, 2, 3, 4 };
	
	printf("b at %p has %d %d %d %d\n", &b, (int) b.x, (int) b.y, (int) b.z, (int) b.awkward);

	struct uniqtype *u = __liballocs_get_inner_type(&b, 1);
	assert(u);
	assert(UNIQTYPE_IS_COMPOSITE_TYPE(u));
	for (struct uniqtype_rel_info *memb = &u->related[0];
				memb < &u->related[u->un.composite.nmemb];
				++memb)
	{
		if (UNIQTYPE_IS_BASE_TYPE(memb->un.memb.ptr))
		{
			printf("Saw a member of bit size %d\n",
				(int) UNIQTYPE_BASE_TYPE_BIT_SIZE(memb->un.memb.ptr));
		}
	}
		
	return 0;
}

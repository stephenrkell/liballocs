#define _GNU_SOURCE
#include <stdlib.h>
#include <liballocs.h>
#include <assert.h>

struct s1
{
	float blah;
	unsigned int ns[1]; // mismatch on signedness, just to mess...
};


int main(void)
{
	void *obj = malloc(sizeof (struct s1) - sizeof (int) + 24);
	struct uniqtype *u = __liballocs_get_alloc_type(obj);
	assert(UNIQTYPE_IS_COMPOSITE_TYPE(u));
	return 0;
}

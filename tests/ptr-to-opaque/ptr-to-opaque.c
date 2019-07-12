#include "allocs.h"

struct T;
struct T *my_t;
extern struct T *other_t;
int main(void)
{
	/* Bug that prompted this regression test:
	 * "we get two distinct pointer types (should be the same), and
	 * __uniqtype__T remains undefined (should be an alias of __uniqtype_05502024_T)".
	 *
	 * Elaborating on that:
	 *
	 * What should happen:
	 * this CU uses codeless __PTR_T
	 * but this gets aliased to the codeful one.
	 *
	 * So let's assert that my_t and other_t have the same type.
	 */
	struct uniqtype *u1 = alloc_get_type(&my_t);
	struct uniqtype *u2 = alloc_get_type(&other_t);
	assert(u1 == u2);
	return 0;
}

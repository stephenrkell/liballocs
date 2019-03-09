#define _GNU_SOURCE
#include <assert.h>
#include <liballocs.h>
#include <stdio.h>
#include <stddef.h>

struct S
{
	union U
	{
		struct T
		{
			short c;
			short extra;
		} t;
		struct V
		{
			short d;
		} v;
	} u;
} s;

_Bool visit_print(struct uniqtype *u, struct uniqtype_containment_ctxt *ucc,
	unsigned u_offset_from_search_start, void *ignored)
{
	fprintf(stderr, "\tSaw a %s at offset %u (%u within its immediate container)\n",
		NAME_FOR_UNIQTYPE(u), u_offset_from_search_start, ucc->u_offset_within_container);
	return 0;
}

int main(void)
{
	struct uniqtype *s_t = __liballocs_get_alloc_type(&s);
	assert(s_t);
	struct uniqtype_rel_info *r = __liballocs_find_span(s_t, 0, NULL);
	assert(r);
	assert(0 == strcmp("U", NAME_FOR_UNIQTYPE(UNIQTYPE_SUBOBJECT_TYPE(s_t, r))));
	assert(UNIQTYPE_SUBOBJECT_OFFSET(s_t, r, 0) == offsetof(struct S, u.t));

	for (unsigned i = 0; i < sizeof (struct S); ++i)
	{
		fprintf(stderr, "Overlapping offset %d within struct S:\n", (int) i);
		__liballocs_search_subobjects_spanning(s_t, i, visit_print, NULL,
			NULL, NULL);
	}
	
	return 0;
}

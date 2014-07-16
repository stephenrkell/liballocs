#include <stdio.h>

const int __liballocs_is_initialized = 1;

int __liballocs_global_init(void)
{
	return 0;
}

void __liballocs_unindex_stack_objects_below(void *stack_addr)
{
}

const void *__liballocs_typestr_to_uniqtype(const void *r)
{
	return NULL;
}

void __index_deep_alloc(void *ptr, int level, unsigned size_bytes) {}
void __unindex_deep_alloc(void *ptr, int level) {}

_Bool __liballocs_find_matching_subobject(signed target_offset_within_uniqtype,
	void *cur_obj_uniqtype, void *test_uniqtype, 
	void **last_attempted_uniqtype, signed *last_uniqtype_offset,
		signed *p_cumulative_offset_searched)
{
	return 0; // failure
}

_Bool 
__liballocs_get_alloc_info
	(const void *obj, 
	const void *test_uniqtype, 
	const char **out_reason,
	const void **out_reason_ptr,
	void *out_memory_kind,
	const void **out_object_start,
	unsigned *out_block_element_count,
	void **out_alloc_uniqtype, 
	const void **out_alloc_site,
	signed *out_target_offset_within_uniqtype)
{
	return 1; // abort
}

struct uniqtype * 
__liballocs_get_alloc_type(void *obj)
{
	return NULL;
}

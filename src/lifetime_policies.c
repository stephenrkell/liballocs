#define _GNU_SOURCE
#include "liballocs_private.h"

#ifndef LIFETIME_POLICIES
#error "This file can only be compiled if LIFETIME_POLICIES is set"
#endif

struct lifetime_policy
{
	// This could be extended in the future to allow other types of policies
	__gc_callback_t addref;
	__gc_callback_t delref;
};

static unsigned __last_free_lifetime_policy_id = 1;
static struct lifetime_policy __lifetime_policies[LIFETIME_POLICIES];

int __liballocs_register_gc_policy(__gc_callback_t addref, __gc_callback_t delref)
{
	int id = __last_free_lifetime_policy_id++;
	if (id > LIFETIME_POLICIES) return -1;

	__lifetime_policies[id] = (struct lifetime_policy)
	{
		.addref = addref,
		.delref = delref
	};

	return id;
}

static inline lifetime_insert_t *get_lifetime_insert_info(const void *obj,
		const void **out_allocstart, void (**out_free_fn)(struct allocated_chunk *))
{
	if ((char *) obj < MINIMUM_USER_ADDRESS || (char *) obj > MAXIMUM_USER_ADDRESS)
		return NULL;

	struct big_allocation *maybe_the_allocation;
	struct allocator *a = __liballocs_leaf_allocator_for(obj, NULL, &maybe_the_allocation);
	if (!a || !ALLOCATOR_HANDLE_LIFETIME_INSERT(a)) return NULL;

	void *allocstart;
	struct liballocs_err *err = a->get_info((void *) obj, maybe_the_allocation,
		NULL, &allocstart, NULL, NULL);
	if (err) return NULL;
	if (out_allocstart) *out_allocstart = allocstart;
	if (out_free_fn) *out_free_fn = a->free;

	return lifetime_insert_for_chunk(allocstart);
}

void __liballocs_attach_lifetime_policy(int policy_id, const void *obj)
{
	assert(policy_id >= 0);

	lifetime_insert_t *lti = get_lifetime_insert_info(obj, NULL, NULL);
	if (lti) *lti |= LIFETIME_POLICY_FLAG(policy_id);
}

void __liballocs_detach_lifetime_policy(int policy_id, const void *obj)
{
	assert(policy_id >= 0);

	const void *allocstart;
	void (*free_fn)(struct allocated_chunk *);
	lifetime_insert_t *lti = get_lifetime_insert_info(obj, &allocstart, &free_fn);
	if (lti)
	{
		*lti &= ~LIFETIME_POLICY_FLAG(policy_id);
		if (!*lti) free_fn((struct allocated_chunk *) allocstart);
	}
}

void __notify_ptr_write(const void **dest, const void *val)
{
	// Called for *dest = val;
	// Override version in liballocs.c
	const void *old_val = *dest;
	const void *old_allocstart;
	lifetime_insert_t *old_lti = get_lifetime_insert_info(old_val, &old_allocstart, NULL);
	if (old_lti && HAS_LIFETIME_POLICIES_ATTACHED(*old_lti))
	{
		// Must be saved on stack to prevent use after free of old_lti
		lifetime_insert_t policies_attached = *old_lti;
		for (unsigned i = 1; i < LIFETIME_POLICIES; ++i)
		{
			if (policies_attached & LIFETIME_POLICY_FLAG(i))
			{
				// old_allocstart destination cannot have been freed if we are here
				__lifetime_policies[i].delref(old_allocstart, dest);
			}
		}
	}

	const void *new_allocstart;
	lifetime_insert_t *new_lti = get_lifetime_insert_info(val, &new_allocstart, NULL);
	if (new_lti && HAS_LIFETIME_POLICIES_ATTACHED(*new_lti))
	{
		for (unsigned i = 1; i < LIFETIME_POLICIES; ++i)
		{
			if (*new_lti & LIFETIME_POLICY_FLAG(i))
			{
				__lifetime_policies[i].addref(new_allocstart, dest);
			}
		}
	}
}

static _Bool need_copy_notification(struct uniqtype *type)
{
	switch (UNIQTYPE_KIND(type))
	{
		case ADDRESS:
			return 1;
		case ARRAY:
			return need_copy_notification(UNIQTYPE_ARRAY_ELEMENT_TYPE(type));
		case COMPOSITE:
			for (int i = 0; i < UNIQTYPE_COMPOSITE_MEMBER_COUNT(type); ++i)
			{
				if (need_copy_notification(type->related[i].un.t.ptr)) return 1;
			}
			return 0;
		default:
			return 0;
	}
}

// Return the size of processed data
static unsigned long notify_copy_for_type(void *dest, const void *src, unsigned long size, struct uniqtype *type)
{
	if (!need_copy_notification(type)) return UNIQTYPE_SIZE_IN_BYTES(type);
	switch (UNIQTYPE_KIND(type))
	{
		case ADDRESS:
			if (size < sizeof(void *)) return size;
			if (src) __notify_ptr_write((const void **)dest, *(const void **)src);
			else __notify_ptr_write((const void **)dest, NULL);
			return sizeof(void *);
		case ARRAY:
		{
			struct uniqtype *elemtyp = UNIQTYPE_ARRAY_ELEMENT_TYPE(type);
			unsigned long elemsize = UNIQTYPE_SIZE_IN_BYTES(elemtyp);
			unsigned nelems = UNIQTYPE_ARRAY_LENGTH(type);
			unsigned long remainsize = size;
			while (remainsize && nelems)
			{
				unsigned long cursize = remainsize > elemsize ? elemsize : remainsize;
				notify_copy_for_type(dest, src, cursize, elemtyp);
				dest += cursize;
				if(src) src += cursize;
				remainsize -= cursize;
				--nelems;
			}
			return size - remainsize;
		}
		case COMPOSITE:
		{
			unsigned nmemb = UNIQTYPE_COMPOSITE_MEMBER_COUNT(type);
			for (int i = 0; i < nmemb; ++i)
			{
				struct uniqtype *membtyp = type->related[i].un.memb.ptr;
				unsigned long memboffset = type->related[i].un.memb.off;
				unsigned long membsize = UNIQTYPE_SIZE_IN_BYTES(membtyp);

				unsigned long maxmembsize = size - memboffset;
				if (maxmembsize < membsize) membsize = maxmembsize;

				notify_copy_for_type(dest + memboffset,
					src ? src + memboffset : NULL, membsize, membtyp);
			}
			return UNIQTYPE_SIZE_IN_BYTES(type) < size ?
				UNIQTYPE_SIZE_IN_BYTES(type) : size;
		}
		default:
			abort();
	}
}

// Similar to __liballocs_get_alloc_type but should not generate any errors
static struct uniqtype *try_get_alloc_type(void *obj)
{
	struct big_allocation *maybe_the_allocation;
	struct allocator *a = __liballocs_leaf_allocator_for(obj, NULL, &maybe_the_allocation);
	if (!a) return NULL;

	// HACK: We want to avoid generating unrecognized heap alloc site errors
	// FIXME: We are still counting aborted queries...
	unsigned unrecognized_heap_alloc_site_count =
		__liballocs_unrecognised_heap_alloc_sites.count;

	struct uniqtype *type;
	struct liballocs_err *err = a->get_info((void *) obj, maybe_the_allocation,
		&type, NULL, NULL, NULL);

	__liballocs_unrecognised_heap_alloc_sites.count = unrecognized_heap_alloc_site_count;
	if (err) return NULL;

	return type;
}

void __notify_copy(void *dest, const void *src, unsigned long n)
{
	// override liballocs.c's version & also wrapped by libcrunch
	if (!__liballocs_is_initialized) return; // Do nothing until initialized
	// Is it too expansive ?? Do we really need to loop ?
	while (n >= sizeof(void *))
	{
		struct uniqtype *typ = try_get_alloc_type(dest);
		if (!typ)
		{
			debug_printf(1, "No type information for copied memory at %p\n", dest);
			return;
		}
		unsigned long handled = notify_copy_for_type(dest, src, n, typ);
		dest += handled;
		src += handled;
		n -= handled;
	}
}

void __notify_free(void *dest)
{
	if (!__liballocs_is_initialized) return; // Do nothing until initialized
	struct uniqtype *typ = try_get_alloc_type(dest);
	if (!typ) return;
	notify_copy_for_type(dest, NULL, UNIQTYPE_SIZE_IN_BYTES(typ), typ);
}


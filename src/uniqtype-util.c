#define _GNU_SOURCE

#include <errno.h>
#include <stdarg.h>
#include <link.h>
#include "librunt.h"
#include "relf.h"
#include "maps.h"
#include "liballocs.h"
#include "liballocs_private.h"

static struct uniqtype *
get_type_from_symname(const char *precise_uniqtype_name)
{
	/* Does such a type exist?
	 * On the assumption that we get called many times for the same typename,
	 * and that usually therefore it *does* exist but in the synthetic libdlbind
	 * object, we try a GNU hash lookup on that first. */
	ElfW(Sym) *found_sym = __liballocs_rt_uniqtypes_gnu_hash ?
		gnu_hash_lookup(__liballocs_rt_uniqtypes_gnu_hash,
			__liballocs_rt_uniqtypes_dynsym, __liballocs_rt_uniqtypes_dynstr,
			precise_uniqtype_name)
		: NULL;
	void *found = (found_sym ? sym_to_addr(found_sym) : NULL);
	if (found) return (struct uniqtype *) found;
	return (struct uniqtype *) dlsym(NULL, precise_uniqtype_name);
}

static
struct uniqtype *
get_or_create_array_type(struct uniqtype *element_t, unsigned array_len)
{
	char precise_uniqtype_name[4096];
	const char *element_name = UNIQTYPE_NAME(element_t); /* gets "simple", not symbol, name */
	if (array_len == UNIQTYPE_ARRAY_LENGTH_UNBOUNDED)
	{
		snprintf(precise_uniqtype_name, sizeof precise_uniqtype_name,
				"__uniqtype____ARR_%s",
				element_name);
	}
	else
	{
		snprintf(precise_uniqtype_name, sizeof precise_uniqtype_name,
				"__uniqtype____ARR%d_%s",
				array_len,
				element_name);
	}
	/* FIXME: compute hash code. Should be an easy case. */

	struct uniqtype *found = get_type_from_symname(precise_uniqtype_name);
	if (found) return found;

	/* Create it and memoise using libdlbind. */
	size_t sz = offsetof(struct uniqtype, related) + 1 * (sizeof (struct uniqtype_rel_info));
	void *allocated = dlalloc(__liballocs_rt_uniqtypes_obj, sz, SHF_WRITE);
	struct uniqtype *allocated_uniqtype = allocated;
	*allocated_uniqtype = (struct uniqtype) {
		.pos_maxoff = (array_len == UNIQTYPE_ARRAY_LENGTH_UNBOUNDED)
				? UNIQTYPE_POS_MAXOFF_UNBOUNDED
				: (array_len * element_t->pos_maxoff),
		.un = {
			array: {
				.is_array = 1,
				.nelems = array_len
			}
		},
		.make_precise = NULL
	};
	allocated_uniqtype->related[0] = (struct uniqtype_rel_info) {
		.un = {
			t: {
				.ptr = element_t
			}
		}
	};
	void *old_base = (void*) ((struct link_map *) __liballocs_rt_uniqtypes_obj)->l_addr;
	void *reloaded = dlbind(__liballocs_rt_uniqtypes_obj, precise_uniqtype_name,
		allocated, sz, STT_OBJECT);
	assert(reloaded);

	return allocated_uniqtype;
}

struct uniqtype *
__liballocs_get_or_create_array_type(struct uniqtype *element_t, unsigned array_len)
{
	if (!element_t || element_t == (void*) -1) return NULL;
	assert(array_len < UNIQTYPE_ARRAY_LENGTH_UNBOUNDED);
	if (element_t->pos_maxoff == 0) return NULL;
	if (element_t->pos_maxoff == UNIQTYPE_POS_MAXOFF_UNBOUNDED) return NULL;
	return get_or_create_array_type(element_t, array_len);
}
struct uniqtype *
__liballocs_get_or_create_unbounded_array_type(struct uniqtype *element_t)
{
	if (!element_t || element_t == (void*) -1) return NULL;
	if (element_t->pos_maxoff == 0) return NULL;
	if (element_t->pos_maxoff == UNIQTYPE_POS_MAXOFF_UNBOUNDED) return NULL;
	return get_or_create_array_type(element_t, UNIQTYPE_ARRAY_LENGTH_UNBOUNDED);
}
struct uniqtype *
__liballocs_get_or_create_flexible_array_type(struct uniqtype *element_t)
{
	assert(element_t);
	if (element_t->pos_maxoff == 0) return NULL;
	if (element_t->pos_maxoff == UNIQTYPE_POS_MAXOFF_UNBOUNDED) return NULL;

	char precise_uniqtype_name[4096];
	const char *element_name = UNIQTYPE_NAME(element_t); /* gets "simple", not symbol, name */
	snprintf(precise_uniqtype_name, sizeof precise_uniqtype_name,
			"__uniqtype____ARR_%s", element_name);
	/* FIXME: compute hash code. */

	struct uniqtype *found = get_type_from_symname(precise_uniqtype_name);
	if (found) return found;

	/* Create it and memoise using libdlbind. */
	size_t sz = offsetof(struct uniqtype, related) + 1 * (sizeof (struct uniqtype_rel_info));
	void *allocated = dlalloc(__liballocs_rt_uniqtypes_obj, sz, SHF_WRITE);
	struct uniqtype *allocated_uniqtype = allocated;
	*allocated_uniqtype = (struct uniqtype) {
		.pos_maxoff = UNIQTYPE_POS_MAXOFF_UNBOUNDED,
		.un = {
			array: {
				.is_array = 1,
				.nelems = UNIQTYPE_ARRAY_LENGTH_UNBOUNDED
			}
		},
		.make_precise = __liballocs_make_array_precise_with_memory_bounds
	};
	allocated_uniqtype->related[0] = (struct uniqtype_rel_info) {
		.un = {
			t: {
				.ptr = element_t
			}
		}
	};
	void *old_base = (void*) ((struct link_map *) __liballocs_rt_uniqtypes_obj)->l_addr;
	void *reloaded = dlbind(__liballocs_rt_uniqtypes_obj, precise_uniqtype_name,
		allocated, sz, STT_OBJECT);
	assert(reloaded);

	return allocated_uniqtype;
}

struct uniqtype *
__liballocs_get_or_create_address_type(const struct uniqtype *pointee_t)
{
	assert(pointee_t);

	char precise_uniqtype_name[4096];
	const char *pointee_name = UNIQTYPE_NAME(pointee_t); /* gets "simple", not symbol, name */
	snprintf(precise_uniqtype_name, sizeof precise_uniqtype_name,
			"__uniqtype____PTR_%s", pointee_name);
	/* FIXME: compute hash code. Should be an easy case. */

	struct uniqtype *found = get_type_from_symname(precise_uniqtype_name);
	if (found) return found;

	int indir_level;
	const struct uniqtype *ultimate_pointee_t;
	if (UNIQTYPE_IS_POINTER_TYPE(pointee_t))
	{
		indir_level = 1 + pointee_t->un.address.indir_level;
		ultimate_pointee_t = UNIQTYPE_ULTIMATE_POINTEE_TYPE(pointee_t);
	}
	else
	{
		indir_level = 1;
		ultimate_pointee_t = pointee_t;
	}

	/* Create it and memoise using libdlbind. */
	size_t sz = offsetof(struct uniqtype, related) + 2 * (sizeof (struct uniqtype_rel_info));
	void *allocated = dlalloc(__liballocs_rt_uniqtypes_obj, sz, SHF_WRITE);
	struct uniqtype *allocated_uniqtype = allocated;
	*allocated_uniqtype = (struct uniqtype) {
		.pos_maxoff = sizeof(void *),
		.un = {
			address: {
				.kind = ADDRESS,
				.indir_level = indir_level,
				.genericity = 0,
			}
		},
		.make_precise = NULL
	};
	allocated_uniqtype->related[0] = (struct uniqtype_rel_info) {
		.un = { t: { .ptr = (struct uniqtype *) pointee_t } }
	};
	allocated_uniqtype->related[1] = (struct uniqtype_rel_info) {
		.un = { t: { .ptr = (struct uniqtype *) ultimate_pointee_t } }
	};
	void *old_base = (void*) ((struct link_map *) __liballocs_rt_uniqtypes_obj)->l_addr;
	void *reloaded = dlbind(__liballocs_rt_uniqtypes_obj, precise_uniqtype_name,
		allocated, sz, STT_OBJECT);
	assert(reloaded);

	return allocated_uniqtype;
}

struct uniqtype *
__liballocs_get_or_create_subprogram_type(struct uniqtype *return_type, unsigned narg, struct uniqtype **arg_types)
{
	assert(return_type);
	assert(narg == 0 || arg_types);

	char precise_uniqtype_name[4096];
	memcpy(precise_uniqtype_name, "__uniqtype____FUN_FROM_", sizeof "__uniqtype____FUN_FROM_");
	unsigned uniqtype_name_pos = sizeof "__uniqtype____FUN_FROM_" - 1;
	for (unsigned i = 0; i < narg; ++i)
	{
		char *uniqtype_arg_name = precise_uniqtype_name + uniqtype_name_pos;
		unsigned bufsz = sizeof precise_uniqtype_name - uniqtype_name_pos;
		uniqtype_name_pos += snprintf(uniqtype_arg_name, bufsz, "__ARG%d_%s", i, UNIQTYPE_NAME(arg_types[i]));
	}

	char *uniqtype_ret_name = precise_uniqtype_name + uniqtype_name_pos;
	unsigned bufsz = sizeof precise_uniqtype_name - uniqtype_name_pos;
	snprintf(uniqtype_ret_name, bufsz, "__FUN_TO_%s", UNIQTYPE_NAME(return_type));

	/* FIXME: compute hash code. */

	struct uniqtype *found = get_type_from_symname(precise_uniqtype_name);
	if (found) return found;

	/* Create it and memoise using libdlbind. */
	size_t sz = offsetof(struct uniqtype, related) + (1+narg) * (sizeof (struct uniqtype_rel_info));
	void *allocated = dlalloc(__liballocs_rt_uniqtypes_obj, sz, SHF_WRITE);
	struct uniqtype *allocated_uniqtype = allocated;
	*allocated_uniqtype = (struct uniqtype) {
		.pos_maxoff = UNIQTYPE_POS_MAXOFF_UNBOUNDED,
		.un = {
			subprogram: {
				.kind = SUBPROGRAM,
				.narg = narg,
				.nret = 1,
				.is_va = 0,
				.cc = 0, // What is the good calling convention choice ?
			}
		},
		.make_precise = NULL,
	};
	allocated_uniqtype->related[0] = (struct uniqtype_rel_info) {
		.un = {
			t: {
				.ptr = return_type
			}
		}
	};
	for (unsigned i = 0; i < narg; i++)
	{
		allocated_uniqtype->related[i+1] = (struct uniqtype_rel_info) {
			.un = {
				t: {
					.ptr = arg_types[i]
				}
			}
		};
	}
	void *old_base = (void*) ((struct link_map *) __liballocs_rt_uniqtypes_obj)->l_addr;
	void *reloaded = dlbind(__liballocs_rt_uniqtypes_obj, precise_uniqtype_name,
		allocated, sz, STT_OBJECT);
	assert(reloaded);

	return allocated_uniqtype;
}

struct uniqtype *
__liballocs_make_array_precise_with_memory_bounds(struct uniqtype *in,
   struct uniqtype *out, unsigned long out_len,
   void *obj, void *memrange_base, unsigned long memrange_sz, void *ip, struct mcontext *ctxt)
{
	unsigned long precise_size = ((char*) memrange_base + memrange_sz) - (char*) obj;
	struct uniqtype *element_t = UNIQTYPE_ARRAY_ELEMENT_TYPE(in);
	assert(element_t);
	assert(element_t->pos_maxoff > 0);
	assert(element_t->pos_maxoff != UNIQTYPE_POS_MAXOFF_UNBOUNDED);
	
	unsigned array_len = precise_size / element_t->pos_maxoff;
	// assert(precise_size % element_t->pos_maxoff == 0); // too strict?
	/* YES it's too strict. For why, see the note under generic_malloc_index.h's 'sizes' diagram. */
	
	return __liballocs_get_or_create_array_type(element_t, precise_size / element_t->pos_maxoff);
}

struct uniqtype *
__liballocs_make_precise_identity(struct uniqtype *in,
   struct uniqtype *out, unsigned long out_len,
   void *obj, void *memrange_base, unsigned long memrange_sz, void *ip, struct mcontext *ctxt)
{
	return in;
}

/* This is the "bzip2 fix". We need the ability to dynamically re-bless memory
 * as a simultaneous combination (union) of a new type and the type it had earlier.
 * PROBLEM: what do we call the union? OK, we can make it anonymous, but we're going
 * (for now) to skip computing the summary code. So build a name by concatenating
 * the constituent element names. */
struct uniqtype *
__liballocs_get_or_create_union_type(unsigned n, /* struct uniqtype *first_memb_t, */...)
{
	if (n == 0) return NULL;
	va_list ap;
	va_start(ap, n);
#define UNION_NAME_MAXLEN 4096
	char union_raw_name[UNION_NAME_MAXLEN] = { '\0' };
	unsigned cur_len = 0;
	struct uniqtype *membs[n]; // ooh, C99 variable-length array...
	unsigned n_left = n;
	unsigned max_len = 0;
	while (n_left > 0)
	{
		struct uniqtype *memb_t = va_arg(ap, struct uniqtype *);
		assert(memb_t);
		assert(memb_t->pos_maxoff > 0);
		assert(memb_t->pos_maxoff != UNIQTYPE_POS_MAXOFF_UNBOUNDED);
		const char *memb_name = NAME_FOR_UNIQTYPE(memb_t);
		membs[n - n_left] = memb_t;
		unsigned len = strlen(memb_name);
		if (cur_len + len >= UNION_NAME_MAXLEN) return NULL;
		strcat(union_raw_name, memb_name);
		if (memb_t->pos_maxoff > max_len) max_len = memb_t->pos_maxoff;
		--n_left;
	}
	char union_uniqtype_name[UNION_NAME_MAXLEN + sizeof "__uniqtype____SYNTHUNION_"] = { '\0' };
	strcat(union_uniqtype_name, "__uniqtype____SYNTHUNION_");
	strcat(union_uniqtype_name, union_raw_name);
#undef UNION_NAME_MAXLEN
	/* FIXME: compute hash code. Should be an easy case. */
	/* Does such a type exist? */
	void *found = NULL;
	if (NULL != (found = dlsym(NULL, union_uniqtype_name)))
	{
		return (struct uniqtype *) found;
	}
	/* Create it and memoise using libdlbind. */
	size_t sz = offsetof(struct uniqtype, related) + n * (sizeof (struct uniqtype_rel_info));
	void *allocated = dlalloc(__liballocs_rt_uniqtypes_obj, sz, SHF_WRITE);
	struct uniqtype *allocated_uniqtype = allocated;
	*allocated_uniqtype = (struct uniqtype) {
		.pos_maxoff = max_len,
		.un = {
			composite: {
				.kind = COMPOSITE,
				.nmemb = n,
				.not_simultaneous = 0
			}
		},
		.make_precise = NULL
	};
	for (unsigned i = 0; i < n; ++i)
	{
		struct uniqtype *memb_t = membs[i];
		allocated_uniqtype->related[i] = (struct uniqtype_rel_info) {
			.un = {
				memb: {
					.ptr = memb_t,
					.off = 0,
					.is_absolute_address = 0,
					.may_be_invalid = 0
				}
			}
		};
	}
	
	void *old_base = (void*) ((struct link_map *) __liballocs_rt_uniqtypes_obj)->l_addr;
	void *reloaded = dlbind(__liballocs_rt_uniqtypes_obj, union_uniqtype_name,
		allocated, sz, STT_OBJECT);
	assert(reloaded);

	return allocated_uniqtype;
}

/* Force a definition of this inline function to be emitted.
 * Debug builds use this, since they won't inline the call to it
 * from the wrapper function. */
int 
__liballocs_walk_subobjects_spanning_rec(
	unsigned accum_offset, unsigned accum_depth,
	const unsigned target_offset_within_u,
	struct uniqtype *u, 
	int (*cb)(struct uniqtype *spans, unsigned span_start_offset, unsigned depth,
		struct uniqtype *containing, struct uniqtype_rel_info *contained_pos, 
		unsigned containing_span_start_offset, void *arg),
	void *arg
	);

const char *(__attribute__((pure)) __liballocs_uniqtype_symbol_name)(const struct uniqtype *u)
{
	if (!u) return NULL;
	Dl_info i = dladdr_with_cache((char *)u + 1);
	if (i.dli_saddr == u)
	{
		return i.dli_sname;
	} else return NULL;
}

const char *(__attribute__((pure)) __liballocs_uniqtype_name)(const struct uniqtype *u)
{
	if (!u) return "(no type)";
	const char *symbol_name = __liballocs_uniqtype_symbol_name(u);
	if (symbol_name)
	{
		if (0 == strncmp(symbol_name, "__uniqtype__", sizeof "__uniqtype__" - 1))
		{
			/* Codeless. */
			return symbol_name + sizeof "__uniqtype__" - 1;
		}
		else if (0 == strncmp(symbol_name, "__uniqtype_", sizeof "__uniqtype_" - 1))
		{
			/* With code. */
			return symbol_name + sizeof "__uniqtype_" - 1 + /* code + underscore */ 9;
		}
		return symbol_name;
	}
	return "(unnamed type)";
}

struct uniqtype *__liballocs_allocsite_to_uniqtype(const void *allocsite)
{ return allocsite_to_uniqtype(allocsite); }

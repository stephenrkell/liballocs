#include <cstdio>
#include <cstdlib>
#include <cassert>
#include <iostream>

#include <boost/icl/interval_set.hpp> 
#include <boost/icl/split_interval_map.hpp> 

using std::cerr;
using std::endl;
using boost::icl::discrete_interval;
using std::make_pair;

typedef bool _Bool;

/* We use this prefix trie to map the address space. */
extern "C"
{
	#include "libcrunch_private.h"
}

std::ostream& operator<<(std::ostream& s, const prefix_tree_node& n);
bool operator==(const prefix_tree_node& arg1, const prefix_tree_node& arg2);
bool operator!=(const prefix_tree_node& arg1, const prefix_tree_node& arg2);

static boost::icl::split_interval_map<uintptr_t, prefix_tree_node> map;

void prefix_tree_add(void *base, size_t s, unsigned kind, const void *data_ptr)
{
	struct node_info info = { .what = DATA_PTR, .un = { data_ptr: data_ptr } };
	prefix_tree_add_full(base, s, kind, &info);
}

void prefix_tree_add_full(void *base, size_t s, unsigned kind, struct node_info *p_arg)
{
	// HACK: use sysconf's page size (it's an assertion anyway)
	assert((uintptr_t) base % sysconf(_SC_PAGE_SIZE) == 0); // else something strange is happening
	
	/* If we already have a mapping for any part of the interval, 
	 * only map those parts that are not already mapped. 
	 * We need this because Linux merges adjacent anonymous memory mappings
	 * in /proc/pid/maps, but we want to preserve the boundaries.
	 * First, compute the map difference
	 *       interval_to_add - existing_intervals
	 * which will leave only the new parts of the interval; */
	
	boost::icl::interval_set<uintptr_t> unmapped;
	unmapped.insert(discrete_interval<uintptr_t>::right_open(
				(uintptr_t) base, 
				(uintptr_t) base + s));
	for (auto i_mapped = map.begin(); i_mapped != map.end(); ++i_mapped)
	{
		unmapped.erase(i_mapped->first);
	}
	
	for (auto i_unmapped = unmapped.begin(); i_unmapped != unmapped.end(); ++i_unmapped)
	{
		map.insert(
			make_pair(
				discrete_interval<uintptr_t>::right_open(
					i_unmapped->lower(),
					i_unmapped->upper()
				), 
				(prefix_tree_node) { kind, *p_arg }
			)
		);
	}
}

void prefix_tree_del(void *base, size_t s)
{
	map.erase(
		discrete_interval<uintptr_t>::right_open(
			(uintptr_t) base, 
			(uintptr_t) base + s
		)
	);
}

enum object_memory_kind prefix_tree_get_memory_kind(const void *obj)
{
	auto found = map.find((uintptr_t) obj);
	if (found == map.end())
	{
		return UNKNOWN;
	}
	return (object_memory_kind) found->second.kind;
}
std::ostream& operator<<(std::ostream& s, const node_info& info)
{
	if (info.what == DATA_PTR) s << "(data ptr) " << info.un.data_ptr;
	else 
	{
		assert(info.what == INS_AND_BITS);
		s << "(insert + bits) " << (void*) (uintptr_t) info.un.ins_and_bits.ins.alloc_site;
	}
	return s;
}
bool operator==(const insert& ins1, const insert& ins2)
{
	return ins1.alloc_site_flag && ins2.alloc_site_flag &&
		ins1.alloc_site && ins2.alloc_site;
		// don't compare prev/next, at least not for now
}
bool operator==(const node_info& info1, const node_info& info2)
{
	return info1.what == info2.what && 
	(info1.what == DATA_PTR ? info1.un.data_ptr == info2.un.data_ptr
	            : (assert(info1.what == INS_AND_BITS), 
					(info1.un.ins_and_bits.ins == info2.un.ins_and_bits.ins
						&& info1.un.ins_and_bits.npages == info2.un.ins_and_bits.npages
						&& info1.un.ins_and_bits.obj_offset == info2.un.ins_and_bits.obj_offset)
					)
	);
}
std::ostream& operator<<(std::ostream& s, const prefix_tree_node& n)
{
	s << "{ " << n.kind << ", " << n.info << "}";
	return s;
}
bool operator==(const prefix_tree_node& arg1, const prefix_tree_node& arg2)
{
	return arg1. kind == arg2.kind && arg1.info == arg2.info;
}
bool operator!=(const prefix_tree_node& arg1, const prefix_tree_node& arg2)
{
	return !(arg1 == arg2);
}
void prefix_tree_print_all_to_stderr(void)
{
	cerr << std::hex << map << std::dec << endl;
}
struct prefix_tree_node *
prefix_tree_deepest_match_from_root(void *base, struct prefix_tree_node ***out_prev_ptr)
{
	if (out_prev_ptr) *out_prev_ptr = NULL;
	auto found = map.find((uintptr_t) base);
	if (found == map.end())
	{
		return NULL;
	} else return const_cast<prefix_tree_node *>(&found->second);
}

struct prefix_tree_node *
prefix_tree_bounds(const void *ptr, const void **out_begin, const void **out_end)
{
	auto found = map.find((uintptr_t) ptr);
	if (found == map.end())
	{
		return NULL;
	} 
	else 
	{
		if (out_begin) *out_begin = reinterpret_cast<void*>(found->first.lower());
		if (out_end) *out_end = reinterpret_cast<void*>(found->first.upper());
		return const_cast<prefix_tree_node *>(&found->second);
	}
}


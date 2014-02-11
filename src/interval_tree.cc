#include <cstdio>
#include <cstdlib>
#include <cassert>
#include <iostream>

#include <boost/icl/interval_map.hpp> 

using std::cerr;
using std::endl;
using boost::icl::discrete_interval;
using std::make_pair;

typedef bool _Bool;

/* We use this prefix trie to map the address space. */
extern "C"
{
#include "libcrunch_private.h"
	void prefix_tree_add(void *base, size_t s, unsigned kind, const void *arg);
	void prefix_tree_del(void *base, size_t s);
	void init_prefix_tree_from_maps(void);
	void prefix_tree_add_missing_maps(void);
	enum object_memory_kind prefix_tree_get_memory_kind(const void *obj);
	void prefix_tree_print_to_stderr(struct prefix_tree_node *start, int indent_level);
}

std::ostream& operator<<(std::ostream& s, const prefix_tree_node& n);
bool operator==(const prefix_tree_node& arg1, const prefix_tree_node& arg2);
bool operator!=(const prefix_tree_node& arg1, const prefix_tree_node& arg2);

static boost::icl::interval_map<uintptr_t, prefix_tree_node> map;

void prefix_tree_add(void *base, size_t s, unsigned kind, const void *arg)
{
	map.insert(
		make_pair(
			discrete_interval<uintptr_t>::right_open(
				(uintptr_t) base, 
				(uintptr_t) base + s
			), 
			(prefix_tree_node) { kind, arg }
		)
	);
}

void prefix_tree_del(void *base, size_t s)
{
	map.erase(
		discrete_interval<uintptr_t>::right_open(			(uintptr_t) base, 
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

std::ostream& operator<<(std::ostream& s, const prefix_tree_node& n)
{
	s << "{ " << n.kind << ", " << n.data_ptr << "}";
	return s;
}
bool operator==(const prefix_tree_node& arg1, const prefix_tree_node& arg2)
{
	return arg1. kind == arg2.kind && arg1.data_ptr == arg2.data_ptr;
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


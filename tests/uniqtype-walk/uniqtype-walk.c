#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <liballocs.h>
#include "uniqtype-bfs.h"

struct list_node
{
	struct stuff
	{
		void *payload;
		void *containing_node; /* just to mess with ya */
	} content;
	struct list_node *next;
};

static int blackened_count;
static void on_blacken(void *obj, struct uniqtype *t, void *arg)
{
	++blackened_count;
	fprintf(stderr, "Blackened an object %p, seen as having type %s\n", 
			obj, UNIQTYPE_NAME(t));
}

int main(void)
{
	/* Build a list of length n */
	const int n = 10;
	const int integers[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
	struct list_node *head = NULL;
	for (int i = 0; i < n; ++i)
	{
		struct list_node *new_node = calloc(1, sizeof (struct list_node));
		assert(new_node);
		new_node->next = head;
		new_node->content.payload = &integers[i];
		new_node->content.containing_node = new_node;
		head = new_node;
	}
	
	// to do make-precise we need the size. FIXME: get_outermost_type should do this
	//struct uniqtype *list_node_t = __liballocs_get_outermost_type(head);

	struct allocator *a;
	const void *alloc_start;
	unsigned long alloc_size_bytes;
	struct uniqtype *list_node_t = NULL;
	struct liballocs_err *err = __liballocs_get_alloc_info(head, &a,
			&alloc_start, &alloc_size_bytes, &list_node_t, /* alloc site */NULL);
	assert(list_node_t);
	if (list_node_t->make_precise)
	{
		// HACK: make_precise is sanity-checking that we get a multiple of 
		// list_node's size, even though we don't because we get some malloc
		// padding. it should know that we only allocated 1. 
		// Kludge the range length for now.
		list_node_t = list_node_t->make_precise(list_node_t, NULL, 0, head, alloc_start,
			/*alloc_size_bytes*/ sizeof (struct list_node), NULL, NULL);
		assert(!list_node_t->make_precise);
	}
	
	/* Use our uniqtype bfs walker to walk the list. */
	__uniqtype_walk_bfs_from_object(head, list_node_t, 
		__uniqtype_default_follow_ptr, NULL, 
		on_blacken, NULL);
	assert(blackened_count == 20); /* 10 nodes, 10 integers -- HMM.
	 Nodes in the graph should really be <void*, uniqtype*> pairs, 
	 to avoid the ambiguity of unadorned pointers.
	 But then each subobject becomes a logically distinct object!
	 Is that what we want? 
	 I suppose it is the logical extension.
	 It raises problems when we have ambiguous views of an object:
	 - is an array[20] also an array[0]? 
	 - is the address of the second element in an array[20] also an array[19]?
	 - what about the hypothetical "null-terminated char array" uniqtype,
	   that dynamically refines itself into a known-length type? 
	 Perhaps the answer is to mark as special ("ground") uniqtypes
	 the ones which don't generate redundant views of memory.
	 Then when we want to iterate over a minimal covering set of 
	 precise views of all memory, we only use ground uniqtypes.
	 It's still unclear, with the null-terminated char array case,
	 how to decompose the memory into ground instances. Perhaps
	 the null-terminated portion as one char[], then the remainding tail
	 as another? Or iteratively decomposed into null-term'd char[]s? 
	 Or just see the tail as allocation padding, like the spare bytes
	 at the end of a malloc()'d chunk?
	 In reality it depends: an ELF strtab is a sequence of char[]s,
	 while a single null-term'd array with some trailing bytes is 
	 one array with padding. So there is some framing intent that
	 we need to capture at the allocation level.
	*/

	return 0;
}

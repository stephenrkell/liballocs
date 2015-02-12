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
			obj, t->name ? t->name : "(no name)");
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
	
	struct uniqtype *list_node_t = __liballocs_get_outermost_type(head);
	assert(list_node_t);
	
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

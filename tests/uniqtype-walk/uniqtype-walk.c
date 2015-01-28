#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <liballocs.h>
#include "uniqtype-bfs.h"

struct node
{
	struct stuff
	{
		void *payload;
		void *containing_node; /* just to mess with ya */
	} content;
	struct node *next;
};

static blackened_count;
static void on_blacken(node_rec *node, void *arg)
{
	++blackened_count;
}

int main(void)
{
	/* Build a list of length n */
	const int n = 10;
	const int integers[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
	struct node *head = NULL;
	for (int i = 0; i < n; ++i)
	{
		struct node *new_node = calloc(1, sizeof (struct node));
		assert(new_node);
		new_node->next = head;
		new_node->content.payload = &integers[i];
		new_node->content.containing_node = new_node;
		head = new_node;
	}
	
	struct uniqtype *node_t = __liballocs_get_outermost_type(head);
	assert(node_t);
	
	/* Use our uniqtype bfs walker to walk the list. */
	__uniqtype_walk_bfs_from_object(head, node_t, 
		__uniqtype_default_make_node, NULL, 
		on_blacken, NULL);
	assert(blackened_count == 20); /* 20 nodes, 20 integers -- HMM */

	return 0;
}

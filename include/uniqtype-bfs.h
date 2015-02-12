#ifndef UNIQTYPE_BFS_H_
#define UNIQTYPE_BFS_H_

// our representation of nodes in the graph
typedef struct __uniqtype_node_rec_s
{ 
	void* obj; 
	struct uniqtype *t;
	void *info;
	void (*free)(void *);
	struct __uniqtype_node_rec_s *next;
} __uniqtype_node_rec; 

static inline void __uniqtype_node_queue_push_tail(__uniqtype_node_rec **q_head, __uniqtype_node_rec **q_tail, __uniqtype_node_rec *to_enqueue)
{
	__uniqtype_node_rec *old_head_node = *q_head;
	__uniqtype_node_rec *old_tail_node = *q_tail;
	assert(!to_enqueue->next);
	*q_tail = to_enqueue;
	if (old_tail_node) old_tail_node->next = to_enqueue;
	else
	{
		assert(!old_head_node);
		/* If we just went from 0 elements to 1, update the head */
		*q_head = to_enqueue;
	}
}

static inline __uniqtype_node_rec *__uniqtype_node_queue_pop_head(__uniqtype_node_rec **q_head, __uniqtype_node_rec **q_tail)
{
	__uniqtype_node_rec *old_head_node = *q_head;
	if (old_head_node)
	{
		*q_head = old_head_node->next;
		/* If we just went from 1 element to 0, clear the tail. */
		if (!*q_head) *q_tail = NULL;
		/* Clear the "next" pointer, since it's not in the queue any more. */
		old_head_node->next = NULL;
	}
	return old_head_node;
}

static inline _Bool __uniqtype_node_queue_empty(void *q_head)
{
	return !q_head;
}

typedef void follow_ptr_fn(void**, struct uniqtype**, void *);
typedef void on_blacken_fn(void *obj, struct uniqtype *t, void *);

void __uniqtype_default_follow_ptr(void**, struct uniqtype**, void *);

void __uniqtype_walk_bfs_from_object(
	void *object, struct uniqtype *t,
	follow_ptr_fn *follow_ptr, void *fp_arg,
	on_blacken_fn *on_blacken, void *ob_arg);

void __uniqtype_process_bfs_queue(
	__uniqtype_node_rec **p_q_head,
	__uniqtype_node_rec **p_q_tail,
	follow_ptr_fn *follow_ptr, void *fp_arg,
	on_blacken_fn *on_blacken, void *ob_arg);


#endif

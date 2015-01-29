#ifndef UNIQTYPE_BFS_H_
#define UNIQTYPE_BFS_H_

// our representation of nodes in the graph
typedef struct node_rec_s
{ 
	void* obj; 
	struct uniqtype *t;
	void *info;
	struct node_rec_s *next;
} node_rec; 

typedef void follow_ptr_fn(void**, struct uniqtype**, void *);
typedef void on_blacken_fn(void *obj, struct uniqtype *t, void *);

void __uniqtype_default_follow_ptr(void**, struct uniqtype**, void *);

void __uniqtype_walk_bfs_from_object(
	void *object, struct uniqtype *t,
	follow_ptr_fn *follow_ptr, void *fp_arg,
	on_blacken_fn *on_blacken, void *ob_arg);

void __uniqtype_process_bfs_queue(
	node_rec **p_q_head,
	node_rec **p_q_tail,
	follow_ptr_fn *follow_ptr, void *fp_arg,
	on_blacken_fn *on_blacken, void *ob_arg);


#endif

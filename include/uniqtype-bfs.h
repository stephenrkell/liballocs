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

typedef node_rec *make_node_fn(void*, struct uniqtype*, void *arg);
typedef void on_blacken_fn(node_rec *, void *);

void __uniqtype_walk_bfs_from_object(
	void *object, struct uniqtype *t,
	make_node_fn *make_node, void *mn_arg,
	on_blacken_fn *on_blacken, void *ob_arg);

void __uniqtype_process_bfs_queue(
	node_rec **p_q_head,
	node_rec **p_q_tail,
	make_node_fn *make_node, void *mn_arg,
	on_blacken_fn *on_blacken, void *ob_arg);

node_rec *__uniqtype_default_make_node(void *obj, struct uniqtype *t, void *arg);

void __uniqtype_default_on_blacken(node_rec *node, void *arg);

#endif

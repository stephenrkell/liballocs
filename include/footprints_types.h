#ifndef __FOOTPRINTS_TYPES_H__
#define __FOOTPRINTS_TYPES_H__

#include <stdbool.h>
#include <stdint.h>
#include "uniqtype.h"

#include "footprints_enums.h"

struct expr;

struct binary_op {
	enum binary_ops op;
	struct expr *left;
	struct expr *right;
};

struct unary_op {
	enum unary_ops op;
	struct expr *arg;
};

struct for_loop {
	struct expr *body;
	char *ident;
	struct expr *over;
};

struct if_cond {
	struct expr *cond;
	struct expr *then;
	struct expr *otherwise;
};

struct subscript {
	struct expr *target;
	enum subscript_methods method;
	struct expr *from;
	struct expr *to;
};

struct object {
	struct uniqtype *type;
	void *addr;
	_Bool direct;
};

struct extent {
	unsigned long base;
	unsigned long length;
};

struct union_node {
	struct expr *expr;
	struct union_node *next;
	int child_n;
};

struct function {
	char *name;
	struct string_node *args;
	struct expr *expr;
};

struct expr {
	enum expr_types type;
	enum footprint_direction direction;
	union {
		struct binary_op binary_op;
		struct unary_op unary_op;
		struct for_loop for_loop;
		struct if_cond if_cond;
		struct subscript subscript;
		struct extent extent;
		struct union_node *unioned;
		struct object object;
		struct function func;
		char *ident;
		int64_t value;
	};
};

struct extent_node {
	struct extent extent;
	struct extent_node *next;
};

struct data_extent {
	size_t base;
	size_t length;
	void *data;
};

struct data_extent_node {
	struct data_extent extent;
	struct data_extent_node *next;
};

struct env_node {
	char *name;
	struct expr *expr;
	struct env_node *next;
};

struct string_node {
	char *value;
	struct string_node *next;
};

struct evaluator_state {
	struct expr *expr;
	struct env_node *toplevel_env;
	struct extent_node *need_memory_extents;
	struct data_extent_node *have_memory_extents;
	struct union_node *result;
	_Bool finished;
};

struct footprint_node {
	char *name;
	char *arg_names[6];
	enum footprint_direction direction;
	struct union_node *exprs;
	struct footprint_node *next;
};

#endif

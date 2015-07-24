#define _GNU_SOURCE

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include <dwarfidl/parser_includes.h>
#include "liballocs.h"
#include "footprints.h"

struct expr *eval_for_loop(struct evaluator_state *state, struct expr *e, struct env_node *env) {
	// f(x) for x in xs -> union(f(x1), f(x2), ... f(xn))
	assert(e->type == EXPR_FOR);

	struct expr *over = eval_footprint_expr(state, e->for_loop.over, env);
	assert(over->type == EXPR_UNION);

	struct union_node *tail = NULL;
	struct union_node *current = over->unioned;
	while (current != NULL) {
		struct env_node *head_env = env_new();
		head_env->name = e->for_loop.ident;
		head_env->expr = eval_footprint_expr(state, current->expr, env);
		head_env->next = env;
		struct union_node *head = union_new();
		head->expr = eval_footprint_expr(state, e->for_loop.body, head_env);
		head->next = tail;
		tail = head;
		current = current->next;
	}

	struct expr *result = expr_new();
	result->type = EXPR_UNION;
	result->unioned = tail;

	return result;
}

struct expr *eval_if_cond(struct evaluator_state *state, struct expr *e, struct env_node *env) {
	assert(e->type == EXPR_IF);
	int64_t cond;
	struct expr *partial_cond;
	if (!eval_to_value(state, e->if_cond.cond, env, &partial_cond, &cond)) {
		// cache miss, state modified
		struct expr *new_e = expr_clone(e);
		new_e->if_cond.cond = partial_cond;
		return new_e;
	}
	if (cond) {
		return eval_footprint_expr(state, e->if_cond.then, env);
	} else {
		return eval_footprint_expr(state, e->if_cond.otherwise, env);
	}
}

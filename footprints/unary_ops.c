#define _GNU_SOURCE

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include <dwarfidl/parser_includes.h>
#include "liballocs.h"
#include "footprints.h"

const char *unary_ops_str[] = {
	"not",
	"-",
	"~",
	"sizeof"
};


struct expr *eval_unary_op(struct evaluator_state *state, struct expr* e, struct env_node *env) {
	assert(e->type == EXPR_UNARY);
	switch (e->unary_op.op) {
	case UN_NOT: {
		int64_t arg;
		struct expr *partial_arg;
		if (!eval_to_value(state, e->unary_op.arg, env, &partial_arg, &arg)) {
			// cache miss, state modified
			struct expr *new_expr = expr_clone(e);
			new_expr->unary_op.arg = partial_arg;
			return new_expr;
		}
		return construct_value(arg ? 0 : 1);
	} break;
	case UN_NEG: {
		int64_t arg;
		struct expr *partial_arg;
		if (!eval_to_value(state, e->unary_op.arg, env, &partial_arg, &arg)) {
			// cache miss, state modified
			struct expr *new_expr = expr_clone(e);
			new_expr->unary_op.arg = partial_arg;
			return new_expr;
		}
		return construct_value(-arg);
	} break;
	case UN_SIZEOF: {
		struct object arg;
		struct expr *partial_arg;
		if (!eval_to_object(state, e->unary_op.arg, env, &partial_arg, &arg)) {
			// cache miss, state modified
			struct expr *new_expr = expr_clone(e);
			new_expr->unary_op.arg = partial_arg;
			return new_expr;
		}
		assert(UNIQTYPE_HAS_KNOWN_LENGTH(arg.type));
		return construct_value(arg.type->pos_maxoff);
	} break;
	default:
		assert(false);
		break;
	}
}

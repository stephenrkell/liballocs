#define _GNU_SOURCE

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include <dwarfidl/parser_includes.h>
#include "liballocs.h"
#include "footprints.h"

const char *binary_ops_str[] = {
	">",
	"<",
	">=",
	"<=",
	"==",
	"!=",
	"and",
	"or",
	"+",
	"-",
	"*",
	"/",
	"%",
	"<<",
	">>",
	"&",
	"|",
	"^",
	".",
	"called with"
};


struct expr *eval_binary_op(struct expr* e, struct env_node *env) {
	assert(e->type == EXPR_BINARY);
	switch (e->binary_op.op) {
	case BIN_GT: {
		int64_t left = eval_to_value(e->binary_op.left, env);
		int64_t right = eval_to_value(e->binary_op.right, env);
		return construct_value(left > right ? 1 : 0);
	} break;
	case BIN_LT: {
		int64_t left = eval_to_value(e->binary_op.left, env);
		int64_t right = eval_to_value(e->binary_op.right, env);
		return construct_value(left < right ? 1 : 0);
	} break;
	case BIN_GTE: {
		int64_t left = eval_to_value(e->binary_op.left, env);
		int64_t right = eval_to_value(e->binary_op.right, env);
		return construct_value(left >= right ? 1 : 0);
	} break;
	case BIN_LTE: {
		int64_t left = eval_to_value(e->binary_op.left, env);
		int64_t right = eval_to_value(e->binary_op.right, env);
		return construct_value(left <= right ? 1 : 0);
	} break;
	case BIN_EQ: {
		int64_t left = eval_to_value(e->binary_op.left, env);
		int64_t right = eval_to_value(e->binary_op.right, env);
		return construct_value(left == right ? 1 : 0);
	} break;
	case BIN_NE: {
		int64_t left = eval_to_value(e->binary_op.left, env);
		int64_t right = eval_to_value(e->binary_op.right, env);
		return construct_value(left != right ? 1 : 0);
	} break;
	case BIN_AND: {
		int64_t left = eval_to_value(e->binary_op.left, env);
		int64_t right = eval_to_value(e->binary_op.right, env);
		return construct_value(!!left && !!right ? 1 : 0);
	} break;
	case BIN_OR: {
		int64_t left = eval_to_value(e->binary_op.left, env);
		int64_t right = eval_to_value(e->binary_op.right, env);
		return construct_value(!!left || !!right ? 1 : 0);
	} break;
	case BIN_ADD: {
		int64_t left = eval_to_value(e->binary_op.left, env);
		int64_t right = eval_to_value(e->binary_op.right, env);
		return construct_value(left + right);
	} break;
	case BIN_SUB: {
		int64_t left = eval_to_value(e->binary_op.left, env);
		int64_t right = eval_to_value(e->binary_op.right, env);
		return construct_value(left - right);
	} break;
	case BIN_MUL: {
		int64_t left = eval_to_value(e->binary_op.left, env);
		int64_t right = eval_to_value(e->binary_op.right, env);
		return construct_value(left * right);
	} break;
	case BIN_DIV: {
		int64_t left = eval_to_value(e->binary_op.left, env);
		int64_t right = eval_to_value(e->binary_op.right, env);
		return construct_value(left / right);
	} break;
	case BIN_MOD: {
		int64_t left = eval_to_value(e->binary_op.left, env);
		int64_t right = eval_to_value(e->binary_op.right, env);
		return construct_value(left % right);
	} break;
	case BIN_SHL: {
		int64_t left = eval_to_value(e->binary_op.left, env);
		int64_t right = eval_to_value(e->binary_op.right, env);
		return construct_value(left << right);
	} break;
	case BIN_SHR: {
		int64_t left = eval_to_value(e->binary_op.left, env);
		int64_t right = eval_to_value(e->binary_op.right, env);
		return construct_value(left >> right);
	} break;
	case BIN_BITAND: {
		int64_t left = eval_to_value(e->binary_op.left, env);
		int64_t right = eval_to_value(e->binary_op.right, env);
		return construct_value(left & right);
	} break;
	case BIN_BITOR: {
		int64_t left = eval_to_value(e->binary_op.left, env);
		int64_t right = eval_to_value(e->binary_op.right, env);
		return construct_value(left | right);
	} break;
	case BIN_BITXOR: {
		int64_t left = eval_to_value(e->binary_op.left, env);
		int64_t right = eval_to_value(e->binary_op.right, env);
		return construct_value(left ^ right);
	} break;
	case BIN_MEMBER: {
		// if left is union:
		//     return eval(x.right_ident for x in left_union)
		// else:
		//     return lookup(left_obj, right_ident)
		assert(e->binary_op.right->type == EXPR_IDENT);
		struct expr *left = eval_footprint_expr(e->binary_op.left, env);
		if (left->type == EXPR_UNION) {
			char *loop_var_name = new_ident_not_in(env, "loop_var");

			struct expr *loop_var_ident = expr_new();
			loop_var_ident->type = EXPR_IDENT;
			loop_var_ident->ident = loop_var_name;

			struct expr *loop_body = expr_new();
			memcpy(loop_body, e, sizeof(struct expr));
			loop_body->binary_op.left = loop_var_ident;

			struct expr *loop = expr_new();
			loop->type = EXPR_FOR;
			loop->for_loop.body = loop_body;
			loop->for_loop.ident = loop_var_name;
			loop->for_loop.over = left;

			return eval_footprint_expr(loop, env);
		} else if (left->type == EXPR_OBJECT) {
			return lookup_in_object(&left->object, e->binary_op.right->ident);
		} else {
			assert(false);
		}
	} break;
	case BIN_APP: {
		struct expr *left = eval_footprint_expr(e->binary_op.left, env);
		struct expr *right = e->binary_op.right;
		assert(left->type == EXPR_FUNCTION);
		assert(right->type == EXPR_FUNCTION_ARGS);
		struct function func = left->func;
		struct env_node *function_env = env;
		struct string_node *current_arg_name = func.args;
		struct union_node *current_arg_value = e->binary_op.right->unioned;
		while (current_arg_value != NULL) {
			assert(current_arg_name != NULL); // not too many arguments
			struct expr *e = eval_footprint_expr(current_arg_value->expr, env);
			function_env = env_new_with(current_arg_name->value, e, function_env);
			current_arg_name = current_arg_name->next;
			current_arg_value = current_arg_value->next;
		}
		assert(current_arg_name == NULL); // not too few arguments
		function_env = env_new_with(func.name, construct_function(func), function_env);
		return eval_footprint_expr(func.expr, function_env);
	} break;
	default:
		assert(false);
		break;
	}
}





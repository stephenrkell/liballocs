#define _GNU_SOURCE

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include <dwarfidl/parser_includes.h>
#include "liballocs.h"
#include "footprints.h"


////////////////////////////////////////////////////////////
// evaluator
////////////////////////////////////////////////////////////


struct expr *eval_footprint_expr(struct evaluator_state *state, struct expr* e, struct env_node *env) {
	assert(e);
	fprintf(stderr, "== eval_footprint_expr called with expr = %s (type = %s), env = ", print_expr_tree(e), expr_types_str[e->type]);
	struct env_node *current = env;
	while (current != NULL) {
		fprintf(stderr, "%s%s", current->name, (current->next == NULL ? "" : ", "));
		current = current->next;
	}
	fprintf(stderr, "\n");
	switch (e->type) {
	case EXPR_VOID:
	case EXPR_VALUE:
	case EXPR_EXTENT:
	case EXPR_OBJECT:
	case EXPR_FUNCTION:
		return e;
		break;
	case EXPR_FOR: {
		return eval_for_loop(state, e, env);
	} break;
	case EXPR_IF: {
		return eval_if_cond(state, e, env);
	} break;
	case EXPR_BINARY: {
		return eval_binary_op(state, e, env);
	} break;
	case EXPR_UNARY: {
		return eval_binary_op(state, e, env);
	} break;
	case EXPR_IDENT: {
		return eval_ident(state, e, env);
	} break;
	case EXPR_SUBSCRIPT: {
		return eval_subscript(state, e, env);
	} break;
	case EXPR_FUNCTION_ARGS:
	case EXPR_UNION: {
		return eval_union(state, e, env);
	} break;
	default:
		assert(false);
	}
}

struct evaluator_state *eval_footprint_with(struct evaluator_state *state, struct footprint_node *footprint, struct env_node *defined_functions, struct uniqtype *func, long int arg_values[6]) {

	struct env_node *env = defined_functions;
	for (uint8_t i = 0; i < 6; i++) {
		if (footprint->arg_names[i] == NULL) {
			break;
		} else {
			struct object o;
			o.type = func->contained[i+1].ptr;
			o.addr = arg_values + i;
			//fprintf(stderr, "created arg %s with type %s and typed value 0x%lx from untyped 0x%lx\n", footprint->arg_names[i], o.type->name, object_to_value(o.type, o.addr), arg_values[i]);
			env = env_new_with(footprint->arg_names[i], construct_object(o), env);
		}
	}

	// eval_footprint_expr will modify *state
	struct expr *evaled = eval_footprint_expr(state, construct_union(footprint->exprs), env);

	if (state->need_memory_extents == NULL) {
		struct union_node *result;
		
		if (evaled->type != EXPR_UNION) {
			result = union_new_with(evaled, NULL);
		} else {
			result = evaled->unioned;
		}
		
		result = union_flatten(result);
		result = _union_remove_type(result, EXPR_VOID);
		result = union_objects_to_extents(result);
		union_sort(&result);
		result = sorted_union_merge_extents(result);
		
		state->result = result;
		state->finished = true;
		return state;
	} else {
		state->expr = evaled;
		state->finished = false;
		return state;
	}
}



struct evaluator_state *eval_footprints_for(struct evaluator_state *state, struct footprint_node *footprints, struct env_node *defined_functions, const char *name, struct uniqtype *func, long int arg_values[6]) {
	struct footprint_node *fp = get_footprints_for(footprints, name);
	if (fp != NULL) {
		fprintf(stderr, "Evaling footprint for %s(0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx)\n", name, arg_values[0], arg_values[1], arg_values[2], arg_values[3], arg_values[4], arg_values[5]);
		struct evaluator_state *result = eval_footprint_with(state, fp, defined_functions, func, arg_values);
		return result;
	} else {
		return NULL;
	}
}

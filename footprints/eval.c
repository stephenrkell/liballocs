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


struct expr *eval_footprint_expr(struct expr* e, struct env_node *env) {
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
		return eval_for_loop(e, env);
	} break;
	case EXPR_IF: {
		return eval_if_cond(e, env);
	} break;
	case EXPR_BINARY: {
		return eval_binary_op(e, env);
	} break;
	case EXPR_UNARY: {
		return eval_binary_op(e, env);
	} break;
	case EXPR_IDENT: {
		return eval_ident(e, env);
	} break;
	case EXPR_SUBSCRIPT: {
		return eval_subscript(e, env);
	} break;
	case EXPR_FUNCTION_ARGS:
	case EXPR_UNION: {
		return eval_union(e, env);
	} break;
	default:
		assert(false);
	}
}

struct union_node *eval_footprint_with(struct footprint_node *footprint, struct env_node *defined_functions, struct uniqtype *func, long int arg_values[6]) {
	struct env_node *env = defined_functions;
	for (uint8_t i = 0; i < 6; i++) {
		if (footprint->arg_names[i] == NULL) {
			break;
		} else {
			struct object o;
			o.type = func->contained[i+1].ptr;
			o.addr = arg_values + i;
			fprintf(stderr, "created arg %s with type %s and typed value 0x%lx from untyped 0x%lx\n", footprint->arg_names[i], o.type->name, object_to_value(o.type, o.addr), arg_values[i]);
			env = env_new_with(footprint->arg_names[i], construct_object(o), env);
		}
	}

	struct expr *evaled = eval_footprint_expr(construct_union(footprint->exprs), env);
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
	return result;
}



struct union_node *eval_footprints_for(struct footprint_node *footprints, struct env_node *defined_functions, const char *name, struct uniqtype *func, long int arg_values[6]) {
	struct footprint_node *fp = get_footprints_for(footprints, name);
	if (fp != NULL) {
		fprintf(stderr, "Evaling footprint for %s(0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx)\n", name, arg_values[0], arg_values[1], arg_values[2], arg_values[3], arg_values[4], arg_values[5]);
		struct union_node *result = eval_footprint_with(fp, defined_functions, func, arg_values);
		fprintf(stderr, "Result:\n%s\n", print_footprint_extents(fp, result));
		return result;
	} else {
		return NULL;
	}
}

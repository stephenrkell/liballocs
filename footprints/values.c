#define _GNU_SOURCE

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include <dwarfidl/parser_includes.h>
#include "liballocs.h"
#include "footprints.h"

_Bool eval_to_value(struct evaluator_state *state, struct expr *e, struct env_node *env, struct expr **out_expr, int64_t *out_result) {
	struct expr *result = eval_footprint_expr(state, e, env);
	if (_can_be_further_evaluated(result->type)) {
		*out_expr = result;
		return false;
	} else {
		if (result->type == EXPR_OBJECT) {
			return object_to_value(state, result->object.type, result->object.addr, out_result);
		} else if (result->type == EXPR_VALUE) {
			*out_result = result->value;
			return true;
		} else {
			assert(false);
		}
	}
}

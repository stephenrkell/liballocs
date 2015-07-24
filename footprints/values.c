#define _GNU_SOURCE

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include <dwarfidl/parser_includes.h>
#include "liballocs.h"
#include "footprints.h"

int64_t eval_to_value(struct expr *e, struct env_node *env) {
	struct expr *result = eval_footprint_expr(e, env);
	if (result->type == EXPR_OBJECT) {
		return object_to_value(result->object.type, result->object.addr);
	} else {
		assert(result->type == EXPR_VALUE);
		return result->value;
	}
}

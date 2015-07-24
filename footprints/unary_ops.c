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


struct expr *eval_unary_op(struct expr* e, struct env_node *env) {
	assert(e->type == EXPR_UNARY);
	switch (e->unary_op.op) {
	case UN_NOT: {
		return construct_value(eval_to_value(e->unary_op.arg, env) ? 0 : 1);
	} break;
	case UN_NEG: {
		return construct_value(-eval_to_value(e->unary_op.arg, env));
	} break;
	case UN_SIZEOF: {
		struct object arg = eval_to_object(e->unary_op.arg, env);
		assert(UNIQTYPE_HAS_KNOWN_LENGTH(arg.type));
		return construct_value(arg.type->pos_maxoff);
	} break;
	default:
		assert(false);
		break;
	}
}

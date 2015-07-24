#define _GNU_SOURCE

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include <dwarfidl/parser_includes.h>
#include "liballocs.h"
#include "footprints.h"

const char *subscript_methods_str[] = {
	"SUBSCRIPT_DIRECT_BYTES",
	"SUBSCRIPT_DEREF_BYTES",
	"SUBSCRIPT_DEREF_SIZES"
};


static struct uniqtype *byte_type = &__uniqtype__unsigned_char$8;

struct union_node *construct_bytes_union(struct object obj, size_t base, size_t length) {
	struct union_node *tail = NULL;
	size_t orig_addr = (size_t) obj.addr + base;
	for (size_t ptr = orig_addr; ptr < (orig_addr + length); ptr++) {
		struct expr *new_byte = expr_new();
		new_byte->type = EXPR_OBJECT;
		new_byte->object.type = byte_type;
		new_byte->object.addr = (void*)ptr;
		struct union_node *head = union_new_with(new_byte, tail);
		tail = head;
	}
	return tail;
}

// TODO: bounds checking?
struct union_node *construct_size_union(struct object obj, size_t base, size_t length) {
	assert(UNIQTYPE_HAS_KNOWN_LENGTH(obj.type));
	struct union_node *tail = NULL;
	size_t size = obj.type->pos_maxoff;
	size_t orig_addr = (size_t) obj.addr + (size * base);
	for (size_t ptr = orig_addr; ptr < (orig_addr + size * length); ptr += size) {
		struct expr *new_obj = expr_new();
		new_obj->type = EXPR_OBJECT;
		new_obj->object.type = obj.type;
		new_obj->object.addr = (void*)ptr;
		struct union_node *head = union_new_with(new_obj, tail);
		tail = head;
	}
	return tail;
}

struct union_node *bytes_union_from_object(struct object obj) {
	assert(UNIQTYPE_HAS_KNOWN_LENGTH(obj.type));
	size_t size = obj.type->pos_maxoff;
	return construct_bytes_union(obj, 0, size);
}


struct expr *eval_subscript(struct expr *e, struct env_node *env) {
	assert(e->type == EXPR_SUBSCRIPT);
	struct expr *target_expr = eval_footprint_expr(e->subscript.target, env);
	if (target_expr->type == EXPR_UNION) {
		char *loop_var_name = new_ident_not_in(env, "loop_var");

		struct expr *loop_var_ident = expr_new();
		loop_var_ident->type = EXPR_IDENT;
		loop_var_ident->ident = loop_var_name;

		struct expr *loop_body = expr_new();
		memcpy(loop_body, e, sizeof(struct expr));
		loop_body->subscript.target = loop_var_ident;

		struct expr *loop = expr_new();
		loop->type = EXPR_FOR;
		loop->for_loop.body = loop_body;
		loop->for_loop.ident = loop_var_name;
		loop->for_loop.over = target_expr;

		return eval_footprint_expr(loop, env);
	} else if (target_expr->type == EXPR_OBJECT) {
		struct object target = target_expr->object;
		int64_t from = eval_to_value(e->subscript.from, env);
		int64_t to, length;
		struct object derefed;
		if (e->subscript.to) {
			to = eval_to_value(e->subscript.to, env);
			if (to == from) {
				return construct_void();
			}
			assert(to > from);
			length = to - from;
		}
		switch (e->subscript.method) {
		case SUBSCRIPT_DIRECT_BYTES: {
			if (e->subscript.to) {
				//return construct_union(construct_bytes_union(target, from, length));
				return construct_extent((unsigned long) target.addr + from, length);
			} else {
				struct object new_obj;
				new_obj.type = byte_type;
				new_obj.addr = (void*)((unsigned long) target.addr + from);
				return construct_object(new_obj);
			}
		} break;
		case SUBSCRIPT_DEREF_BYTES:
			derefed = deref_object(target);
			if (e->subscript.to) {
				//return construct_union(construct_bytes_union(derefed, from, length));
				return construct_extent((unsigned long) derefed.addr + from, length);
			} else {
				struct object new_obj;
				new_obj.type = byte_type;
				new_obj.addr = (void*)((unsigned long) derefed.addr + from);
				return construct_object(new_obj);
			}
		case SUBSCRIPT_DEREF_SIZES:
			derefed = deref_object(target);
			assert(UNIQTYPE_HAS_KNOWN_LENGTH(derefed.type));
			size_t size = derefed.type->pos_maxoff;
			if (e->subscript.to) {
				return construct_union(construct_size_union(derefed, from, length));
			} else {
				struct object new_obj = derefed;
				new_obj.addr = (void*) ((size_t)derefed.addr + (from * size));
				return construct_object(new_obj);
			}
		default:
			assert(false);
			break;
		}
	} else {
		assert(false);
	}
}

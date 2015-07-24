#define _GNU_SOURCE

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include <dwarfidl/parser_includes.h>
#include "liballocs.h"
#include "uniqtype.h"
#include "footprints.h"

// returns true if succeeded, false if added to needed_list
_Bool object_to_value(struct evaluator_state *state, struct uniqtype *type, void *addr, int64_t *out_result) {
	assert(UNIQTYPE_HAS_KNOWN_LENGTH(type));
	// traverse the have_extents list looking for what we need
	struct data_extent_node *current = state->have_memory_extents;

	fprintf(stderr, "trying to object_to_value a '%s' at 0x%16lx\n", type->name, (size_t)addr);
	fprintf(stderr, "looking in cache for memory extent base = 0x%16lx, length = 0x%8x\n", (size_t)addr, type->pos_maxoff);
	while (current != NULL) {
		fprintf(stderr, "considering base = 0x%16lx, length = 0x%16lx\n", current->extent.base, current->extent.length);
		if ((size_t)addr >= current->extent.base
		    && ((size_t)addr + type->pos_maxoff) <= (current->extent.base + current->extent.length)) {
			// this extent contains it
			fprintf(stderr, "found it in base = 0x%16lx, length = 0x%16lx\n", current->extent.base, current->extent.length);
			int64_t result;
			void *bytes = (void*)(current->extent.base + (((size_t)addr) - current->extent.base));
			// signed int16 seems to be missing from uniqtypes?
			//if (type == &__uniqtype_int$16) {
			//result = (*(int16_t*)bytes);
			//	} else 
			if (type == &__uniqtype__int$32) {
				result = (int64_t)(*(int32_t*)bytes);
			} else if (type == &__uniqtype__int$64) {
				result = (int64_t)(*(int64_t*)bytes);
			} else if (type == &__uniqtype__uint$16) {
				result = (int64_t)(*(uint16_t*)bytes);
			} else if (type == &__uniqtype__uint$32) {
				result = (int64_t)(*(uint32_t*)bytes);
			} else if (type == &__uniqtype__uint$64) {
				result = (int64_t)(*(uint64_t*)bytes);
			} else if (type == &__uniqtype__signed_char$8) {
				result = (int64_t)(*(int8_t*)bytes);
			} else if (type == &__uniqtype__unsigned_char$8) {
				result = (int64_t)(*(uint8_t*)bytes);
			} else if (UNIQTYPE_IS_POINTER_TYPE(type)) {
				// aaaaaaaa scary
				result = (int64_t)(*(void**)bytes);
			} else {
				fprintf(stderr, "\ndon't know how to convert a '%s' to value!\n", type->name);
				assert(false);
			}

			*out_result = result;
			return true;
		}

		current = current->next;
	}

	// not found
	fprintf(stderr, "DIDN'T find it, adding to need_memory_extents and returning unevaluated\n");
	state->need_memory_extents = extent_node_new_with((size_t) addr, type->pos_maxoff, state->need_memory_extents);
	return false;
}

_Bool eval_to_object(struct evaluator_state *state, struct expr *e, struct env_node *env, struct expr **out_expr, struct object *out_object) {
	struct expr *result = eval_footprint_expr(state, e, env);
	if (_can_be_further_evaluated(result->type)) {
		*out_expr = result;
		return false;
	} else {
		assert(result->type == EXPR_OBJECT);
		*out_object = result->object;
		return true;
	}
}


_Bool deref_object(struct evaluator_state *state, struct object ptr, struct object *out_object) {
	assert(UNIQTYPE_IS_POINTER_TYPE(ptr.type));
	struct object obj;
	obj.type = UNIQTYPE_POINTEE_TYPE(ptr.type);
	int64_t ptr_val;
	if (object_to_value(state, ptr.type, ptr.addr, &ptr_val)) {
		obj.addr = (void*) ptr_val;
		*out_object = obj;
		return true;
	} else {
		return false;
	}
}

struct expr *extent_from_object(struct object obj) {
	assert(UNIQTYPE_HAS_KNOWN_LENGTH(obj.type));
	size_t size = obj.type->pos_maxoff;
	return construct_extent((unsigned long) obj.addr, size);
}

struct data_extent_node *data_extent_node_new() {
	struct data_extent_node *result = malloc(sizeof(struct data_extent_node));
	memset(result, 0, sizeof(struct data_extent_node));
	return result;
}

struct data_extent_node *data_extent_node_new_with(size_t base, size_t length, void *data, struct data_extent_node *next) {
	struct data_extent_node *result = data_extent_node_new();
	result->extent.base = base;
	result->extent.length = length;
	result->extent.data = data;
	result->next = next;
	return result;
}

struct extent_node *extent_node_new() {
	struct extent_node *result = malloc(sizeof(struct extent_node));
	memset(result, 0, sizeof(struct extent_node));
	return result;
}

struct extent_node *extent_node_new_with(size_t base, size_t length, struct extent_node *next) {
	struct extent_node *result = extent_node_new();
	result->extent.base = base;
	result->extent.length = length;
	result->next = next;
	return result;
}

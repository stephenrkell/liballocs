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
int64_t object_to_value(struct uniqtype *type, void *addr/*, int64_t *out_result*/) {
	
	assert(UNIQTYPE_HAS_KNOWN_LENGTH(type));
	// traverse the have_extents list looking for what we need
	//struct data_extent_node current = state->have_extents;
	//while (current == NULL) {
	//	if (addr >= current->base
	//	    && (addr + type->pos_maxoff) <= (current->base + current->length)) {
			// this extent contains it
			int64_t result;
			//		void *bytes = current->base + (addr - current->base);
			void *bytes = addr;

/*if (type == &__uniqtype_int$16) {
				result = (*(int16_t*)bytes);
				} else */if (type == &__uniqtype__int$32) {
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
				fprintf(stderr, "\nBUG. don't know how to convert a '%s' to value! this should never happen.\n", type->name);
				assert(false);
			}

return result;
/**out_result = result;
			return true;
		} else {
			return false;
		}
	}

	// not found
	return false;*/
}

struct object eval_to_object(struct expr *e, struct env_node *env) {
	struct expr *result = eval_footprint_expr(e, env);
	assert(result->type == EXPR_OBJECT);
	return result->object;
}


struct object deref_object(struct object ptr) {
	assert(UNIQTYPE_IS_POINTER_TYPE(ptr.type));
	struct object obj;
	obj.type = UNIQTYPE_POINTEE_TYPE(ptr.type);
	// aaaaaaaa scary
	obj.addr = *(void**)ptr.addr;
	return obj;
}

struct expr *extent_from_object(struct object obj) {
	assert(UNIQTYPE_HAS_KNOWN_LENGTH(obj.type));
	size_t size = obj.type->pos_maxoff;
	return construct_extent((unsigned long) obj.addr, size);
}

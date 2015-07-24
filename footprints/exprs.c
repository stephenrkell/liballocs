#define _GNU_SOURCE

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include <dwarfidl/parser_includes.h>
#include "liballocs.h"
#include "footprints.h"

const char *expr_types_str[] = {
	"EXPR_VOID",
	"EXPR_BINARY",
	"EXPR_UNARY",
	"EXPR_FOR",
	"EXPR_IF",
	"EXPR_SUBSCRIPT",
	"EXPR_EXTENT",
	"EXPR_UNION",
	"EXPR_OBJECT",
	"EXPR_IDENT",
	"EXPR_VALUE",
	"EXPR_FUNCTION",
	"EXPR_FUNCTION_ARGS"
};


////////////////////////////////////////////////////////////
// struct expr
////////////////////////////////////////////////////////////

struct expr *expr_new() {
	struct expr *result = malloc(sizeof(struct expr));
	memset(result, 0, sizeof(struct expr));
	return result;
}

struct expr *expr_clone(struct expr *other) {
	struct expr *result = expr_new();
	memcpy(result, other, sizeof(struct expr));
	return result;
}


struct string_node *string_node_new() {
	struct string_node *result = malloc(sizeof(struct string_node));
	memset(result, 0, sizeof(struct string_node));
	return result;
}

struct string_node *string_node_new_with(char *value, struct string_node *next) {
	struct string_node *result = string_node_new();
	result->value = value;
	result->next = next;
	return result;
}

struct expr *construct_void() {
	struct expr *result = expr_new();
	result->type = EXPR_VOID;
	return result;
}

struct expr *construct_extent(int64_t base, int64_t length) {
	struct expr *result = expr_new();
	result->type = EXPR_EXTENT;
	result->extent.base = base;
	result->extent.length = length;
	return result;
}

struct expr *construct_function(struct function func) {
	struct expr *result = expr_new();
	result->type = EXPR_FUNCTION;
	result->func = func;
	return result;
}

struct expr *construct_value(int64_t value) {
	struct expr *result = expr_new();
	result->type = EXPR_VALUE;
	result->value = value;
	return result;
}

struct expr *construct_union(struct union_node *value) {
	struct expr *result = expr_new();
	result->type = EXPR_UNION;
	result->unioned = value;
	return result;
}

struct expr *construct_object(struct object value) {
	struct expr *result = expr_new();
	result->type = EXPR_OBJECT;
	result->object = value;
	return result;
}

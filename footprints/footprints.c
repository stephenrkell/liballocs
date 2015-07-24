#define _GNU_SOURCE

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include <dwarfidl/parser_includes.h>
#include "liballocs.h"
#include "footprints.h"

const char *footprint_direction_str[] = {
	"read",
	"write",
	"readwrite"
};

////////////////////////////////////////////////////////////
// struct footprint_node
////////////////////////////////////////////////////////////

struct footprint_node *footprint_node_new() {
	struct footprint_node *result = malloc(sizeof(struct footprint_node));
	memset(result, 0, sizeof(struct footprint_node));
	return result;
}

struct footprint_node *footprint_node_new_with(char *name, char *arg_names[static 6], enum footprint_direction direction, struct union_node *exprs, struct footprint_node *next) {
	struct footprint_node *result = footprint_node_new();
	result->name = name;
	for (uint8_t i = 0; i < 6; i++) {
		result->arg_names[i] = arg_names[i];
	}
	result->exprs = exprs;
	result->next = next;
	result->direction = direction;
	return result;
}

void footprint_node_free(struct footprint_node **node) {
	free(*node);
	*node = NULL;
}

void footprint_free(struct footprint_node *head) {
	struct footprint_node *current = head;
	struct footprint_node *next = NULL;
	while (current != NULL) {
		next = current->next;
		footprint_node_free(&current);
		current = next;
	}
}

struct footprint_node *get_footprints_for(struct footprint_node *footprints, const char *name) {
	struct footprint_node *current = footprints;
	while (current != NULL) {
		if (strcmp(name, current->name) == 0) {
			return current;
		}
		current = current->next;
	}

	// not found
	return NULL;
}





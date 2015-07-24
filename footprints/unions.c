#define _GNU_SOURCE

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include <dwarfidl/parser_includes.h>
#include "liballocs.h"
#include "footprints.h"

////////////////////////////////////////////////////////////
// struct union_node
////////////////////////////////////////////////////////////

struct union_node *union_new() {
	struct union_node *result = malloc(sizeof(struct union_node));
	memset(result, 0, sizeof(struct union_node));
	result->child_n = -1;
	return result;
}

struct union_node *union_new_with(struct expr *e, struct union_node *next) {
	struct union_node *result = union_new();
	result->expr = e;
	result->next = next;
	return result;
}

struct union_node *union_union(struct union_node *first, struct union_node *second) {
	if (first == NULL && second == NULL) {
		return NULL;
	} else if (first == NULL) {
		return second;
	} else if (second == NULL) {
		return first;
	} else {
		struct union_node *end = first;
		while (end->next != NULL) {
			end = end->next;
		}
		end->next = second;
		return first;
	}
}

struct union_node *union_add(struct union_node *first, struct expr *e) {
	return union_union(first, union_new_with(e, NULL));
}

void union_free_node(struct union_node **node) {
	free(*node);
	*node = NULL;
}

void union_free(struct union_node *first) {
	struct union_node *current = first;
	struct union_node *next;
	while (current != NULL) {
		next = current->next;
		union_free_node(&current);
		current = next;
	}
}

struct union_node *_union_sort_merge(struct union_node *front, struct union_node *back) {
	if (front == NULL) {
		return back;
	} else if (back == NULL) {
		return front;
	} else {
		void *front_addr, *back_addr;
		switch (front->expr->type) {
		case EXPR_OBJECT:
			front_addr = (void*) front->expr->object.addr;
			break;
		case EXPR_EXTENT:
			front_addr = (void*) front->expr->extent.base;
			break;
		default:
			assert(false);
		}
		switch (back->expr->type) {
		case EXPR_OBJECT:
			back_addr = (void*) back->expr->object.addr;
		case EXPR_EXTENT:
			back_addr = (void*) back->expr->extent.base;
			break;
		default:
			assert(false);
		}
		if (front_addr <= back_addr) {
			front->next = _union_sort_merge(front->next, back);
			return front;
		} else {
			back->next = _union_sort_merge(front, back->next);
			return back;
		}
	}
}


void union_halves(struct union_node *head, struct union_node **front, struct union_node **back) {
	if (head == NULL || head->next == NULL) {
		*front = head;
		*back = NULL;
	} else {
		struct union_node *slow = head;
		struct union_node *fast = head->next;

		while (fast != NULL) {
			fast = fast->next;
			if (fast != NULL) {
				fast = fast->next;
				slow = slow->next;
			}
		}

		*front = head;
		*back = slow->next;
		slow->next = NULL;
	}
}

struct union_node *union_flatten(struct union_node *first) {
	if (first == NULL) {
		return NULL;
	}
	struct union_node *tail = NULL;
	struct union_node *current = first;
	struct union_node *next = NULL;
	while (current != NULL) {
		next = current->next;
		if (current->expr->type == EXPR_UNION) {
			tail = union_union(union_flatten(current->expr->unioned), tail);
		} else {
			current->next = tail;
			tail = current;
		}
		current = next;
	}

	return tail;
}

void union_sort(struct union_node **head) {
	if (head == NULL || *head == NULL || (*head)->next == NULL) {
		return;
	} else {
		struct union_node *front, *back;
		union_halves(*head, &front, &back);
		union_sort(&front);
		union_sort(&back);
		*head = _union_sort_merge(front, back);
	}
}

struct union_node *union_objects_to_extents(struct union_node *head) {
	struct union_node *current = head;
	unsigned long base, length;
	while (current != NULL) {
		if (current->expr->type == EXPR_OBJECT) {
			assert(UNIQTYPE_HAS_KNOWN_LENGTH(current->expr->object.type));
			base = (unsigned long) current->expr->object.addr;
			length = current->expr->object.type->pos_maxoff;
			current->expr->type = EXPR_EXTENT;
			current->expr->extent.base = base;
			current->expr->extent.length = length;
		}
		current = current->next;
	}
	return head;
}

size_t union_size(struct union_node *head) {
	struct union_node *current = head;
	size_t size = 0;
	while (current != NULL) {
		size++;
		current = current->next;
	}

	return size;
}

struct union_node *sorted_union_merge_extents(struct union_node *head) {
	struct union_node *current = head;
	struct union_node *extents = NULL;
	struct union_node *next = NULL;
	unsigned long base, length;
	while (current != NULL) {
		if (current->expr->type == EXPR_VOID) {
			current = current->next;
			continue;
		}
		assert(current->expr->type == EXPR_EXTENT);
		base = current->expr->extent.base;
		length = current->expr->extent.length;
		next = current->next;
		while (next != NULL && next->expr->type == EXPR_EXTENT && next->expr->extent.base <= base + length) {
			length = (next->expr->extent.base + next->expr->extent.length) - base;
			next = next->next;
		}

		extents = union_new_with(construct_extent(base, length), extents);
		current = next;
	}

	return extents;
}


struct expr *eval_union(struct expr *e, struct env_node *env) {
	assert(e->type == EXPR_UNION);
	struct union_node *current = e->unioned;
	struct union_node *tail = NULL;
	while (current != NULL) {
		tail = union_new_with(eval_footprint_expr(current->expr, env), tail);
		current = current->next;
	}
	return construct_union(tail);
}

struct union_node *_union_remove_type(struct union_node *head, enum expr_types type) {
	if (head == NULL) {
		return NULL;
	} else {

		struct union_node *current = head;
		struct union_node *tail = NULL;
		while (current != NULL) {
			if (current->expr->type != type) {
				tail = union_new_with(current->expr, tail);
			}

			current = current->next;
		}

		return tail;
	}
}


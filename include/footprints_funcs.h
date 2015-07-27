#ifndef __FOOTPRINTS_FUNCS_H__
#define __FOOTPRINTS_FUNCS_H__

#include <stdbool.h>
#include <stdint.h>
#include "uniqtype.h"

#include "footprints_enums.h"
#include "footprints_types.h"


////////////////////////////////////////////////////////////
// parser
////////////////////////////////////////////////////////////

struct footprint_node *parse_footprints_from_file(const char *filename, struct env_node **output_env);

struct footprint_node *new_from_subprogram_DIE(void *subprogram, struct footprint_node *next);
struct expr *parse_antlr_tree(void *ast);

char *parse_ident(void *ast);
int64_t parse_int(void *ast);
struct function parse_function(void *ast);

////////////////////////////////////////////////////////////
// printers
////////////////////////////////////////////////////////////

char *print_expr_tree(struct expr *e);
char *print_footprint_extents(struct footprint_node *fp, struct union_node *extents);
void print_tree_types(void *ast);

////////////////////////////////////////////////////////////
// evaluator
////////////////////////////////////////////////////////////

struct evaluator_state *eval_footprints_for(struct evaluator_state *state, struct footprint_node *footprints, struct env_node *defined_functions, const char *name, struct uniqtype *func, long int arg_values[6]);
struct evaluator_state *eval_footprint_with(struct evaluator_state *state, struct footprint_node *footprint, struct env_node *defined_functions, struct uniqtype *func, long int arg_values[6]);

struct expr *eval_footprint_expr(struct evaluator_state *state, struct expr *e, struct env_node *env);

struct expr *eval_binary_op(struct evaluator_state *state, struct expr* e, struct env_node *env);
struct expr *eval_unary_op(struct evaluator_state *state, struct expr* e, struct env_node *env);
struct expr *eval_for_loop(struct evaluator_state *state, struct expr *e, struct env_node *env);
struct expr *eval_if_cond(struct evaluator_state *state, struct expr *e, struct env_node *env);
struct expr *eval_subscript(struct evaluator_state *state, struct expr *e, struct env_node *env);
struct expr *eval_ident(struct evaluator_state *state, struct expr *e, struct env_node *env);
struct expr *eval_union(struct evaluator_state *state, struct expr *e, struct env_node *env);

_Bool eval_to_value(struct evaluator_state *state, struct expr *e, struct env_node *env, struct expr **out_expr, int64_t *out_result);
char *eval_to_ident(struct evaluator_state *state, struct expr *e, struct env_node *env);
_Bool eval_to_object(struct evaluator_state *state, struct expr *e, struct env_node *env, struct expr **out_expr, struct object *out_object);

static inline _Bool _can_be_further_evaluated(enum expr_types type) {
	switch (type) {
	case EXPR_BINARY:
	case EXPR_UNARY:
	case EXPR_FOR:
	case EXPR_IF:
	case EXPR_SUBSCRIPT:
		return true;
	default:
		return false;
	}
}


////////////////////////////////////////////////////////////
// memory
////////////////////////////////////////////////////////////

struct data_extent_node *data_extent_node_new();
struct data_extent_node *data_extent_node_new_with(size_t base, size_t length, void *data, struct data_extent_node *next);

struct extent_node *extent_node_new();
struct extent_node *extent_node_new_with(size_t base, size_t length, struct extent_node *next);

_Bool object_to_value(struct evaluator_state *state, struct object object, int64_t *out_result);
_Bool deref_object(struct evaluator_state *state, struct object pointer, struct object *out_object);

////////////////////////////////////////////////////////////
// exprs
////////////////////////////////////////////////////////////

struct expr *expr_new();
struct expr *expr_clone(struct expr *other);
void expr_free(struct expr **e);

struct expr *construct_void();
struct expr *construct_extent(int64_t base, int64_t length);
struct expr *construct_function(struct function func);
struct expr *construct_value(int64_t value);
struct expr *construct_union(struct union_node *value);
struct expr *construct_object(struct object value);

struct string_node *string_node_new();
struct string_node *string_node_new_with(char *value, struct string_node *next);
void string_node_free(struct string_node **node);

////////////////////////////////////////////////////////////
// idents
////////////////////////////////////////////////////////////

struct env_node *env_new();
struct env_node *env_new_with(char *name, struct expr *expr, struct env_node *next);
void env_free_node(struct env_node **node);
void env_free(struct env_node *first);

char *new_ident_not_in(struct env_node *env, char *suffix);
char *_find_ident_not_in(struct env_node *env, char *suffix, size_t length);
_Bool _ident_in(struct env_node *env, char *ident);
struct expr *lookup_in_object(struct object *context, char *ident);
struct expr *lookup_in_env(struct env_node *env, char *ident);


////////////////////////////////////////////////////////////
// unions
////////////////////////////////////////////////////////////

struct union_node *union_new();
struct union_node *union_new_with(struct expr *e, struct union_node *next);
void union_free_node(struct union_node **node);

struct union_node *union_union(struct union_node *first, struct union_node *second);
struct union_node *union_add(struct union_node *first, struct expr *e);
void union_free(struct union_node *first);
struct union_node *union_flatten(struct union_node *first);
void union_sort(struct union_node **head);
struct union_node *union_objects_to_extents(struct union_node *head);
struct union_node *sorted_union_merge_extents(struct union_node *head);

struct union_node *_union_remove_type(struct union_node *head, enum expr_types type);

////////////////////////////////////////////////////////////
// footprints
////////////////////////////////////////////////////////////

struct footprint_node *footprint_node_new();
struct footprint_node *footprint_node_new_with(char *name, char *arg_names[6], enum footprint_direction direction, struct union_node *exprs, struct footprint_node *next);
void footprint_node_free(struct footprint_node **node);
void footprint_free(struct footprint_node *node);

struct footprint_node *get_footprints_for(struct footprint_node *footprints, const char *name);

#endif

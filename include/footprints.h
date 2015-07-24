#ifndef FOOTPRINTS_H_
#define FOOTPRINTS_H_


#include <stdbool.h>
#include <stdint.h>
#include "uniqtype.h"

////////////////////////////////////////////////////////////
// structs
////////////////////////////////////////////////////////////

struct expr;

extern const char *binary_ops_str[];
extern const char *unary_ops_str[];
extern const char *subscript_methods_str[];
extern const char *expr_types_str[];
extern const char *footprint_direction_str[];


enum binary_ops {
	 BIN_GT,
	 BIN_LT,
	 BIN_GTE,
	 BIN_LTE,
	 BIN_EQ,
	 BIN_NE,
	 BIN_AND,
	 BIN_OR,
	 BIN_ADD,
	 BIN_SUB,
	 BIN_MUL,
	 BIN_DIV,
	 BIN_MOD,
	 BIN_SHL,
	 BIN_SHR,
	 BIN_BITAND,
	 BIN_BITOR,
	 BIN_BITXOR,
	 BIN_MEMBER,
	 BIN_APP
};


enum unary_ops {
	 UN_NOT,
	 UN_NEG,
	 UN_BITNOT,
	 UN_SIZEOF
};


enum subscript_methods {
	 SUBSCRIPT_DIRECT_BYTES,
	 SUBSCRIPT_DEREF_BYTES,
	 SUBSCRIPT_DEREF_SIZES
};


enum expr_types {
	 EXPR_VOID,
	 EXPR_BINARY,
	 EXPR_UNARY,
	 EXPR_FOR,
	 EXPR_IF,
	 EXPR_SUBSCRIPT,
	 EXPR_EXTENT,
	 EXPR_UNION,
	 EXPR_OBJECT,
	 EXPR_IDENT,
	 EXPR_VALUE,
	 EXPR_FUNCTION,
	 EXPR_FUNCTION_ARGS,
};



struct binary_op {
	 enum binary_ops op;
	 struct expr *left;
	 struct expr *right;
};

struct unary_op {
	 enum unary_ops op;
	 struct expr *arg;
};

struct for_loop {
	 struct expr *body;
	 char *ident;
	 struct expr *over;
};

struct if_cond {
	 struct expr *cond;
	 struct expr *then;
	 struct expr *otherwise;
};

struct subscript {
	 struct expr *target;
	 enum subscript_methods method;
	 struct expr *from;
	 struct expr *to;
};

struct object {
	 struct uniqtype *type;
	 void *addr;
};

struct extent {
	 unsigned long base;
	 unsigned long length;
};

struct union_node {
	 struct expr *expr;
	 struct union_node *next;
	 int child_n;
};

struct env_node {
	 char *name;
	 struct expr *expr;
	 struct env_node *next;
};

struct string_node {
	 char *value;
	 struct string_node *next;
};

struct function {
	 char *name;
	 struct string_node *args;
	 struct expr *expr;
};

struct expr {
	 enum expr_types type;
	 union {
		  struct binary_op binary_op;
		  struct unary_op unary_op;
		  struct for_loop for_loop;
		  struct if_cond if_cond;
		  struct subscript subscript;
		  struct extent extent;
		  struct union_node *unioned;
		  struct object object;
		  struct function func;
		  char *ident;
		  int64_t value;
	 };
};

enum footprint_direction {
	 FOOTPRINT_READ,
	 FOOTPRINT_WRITE,
	 FOOTPRINT_READWRITE
};

struct footprint_node {
	 char *name;
	 char *arg_names[6];
	 enum footprint_direction direction;
	 struct union_node *exprs;
	 struct footprint_node *next;
};

/*struct footprint {
  struct uniqtype *context;
  int type; // r, w, rw
  struct expr *value;
  struct footprint *next;
  };
  
  struct name_node {
  char *ident;
  struct footprint *prints;
  struct name_node *next;
  };*/


////////////////////////////////////////////////////////////
// evaluator
////////////////////////////////////////////////////////////

struct expr *eval_footprint_expr(struct expr *e, struct env_node *env);
int64_t eval_to_value(struct expr *e, struct env_node *env);
char *eval_to_ident(struct expr *e, struct env_node *env);
struct object eval_to_object(struct expr *e, struct env_node *env);
struct expr *construct_value(int64_t value);
struct expr *construct_object(struct object value);
struct expr *eval_binary_op(struct expr* e, struct env_node *env); 
char *new_ident_not_in(struct env_node *env, char *suffix);
char *_find_ident_not_in(struct env_node *env, char *suffix, size_t length);
_Bool _ident_in(struct env_node *env, char *ident);
struct expr *eval_unary_op(struct expr* e, struct env_node *env);
struct expr *eval_for_loop(struct expr *e, struct env_node *env);
struct expr *eval_if_cond(struct expr *e, struct env_node *env);
struct expr *eval_subscript(struct expr *e, struct env_node *env);
struct expr *lookup_in_object(struct object *context, char *ident);
struct expr *lookup_in_env(struct env_node *env, char *ident);
struct expr *eval_ident(struct expr *e, struct env_node *env);
struct expr *eval_union(struct expr *e, struct env_node *env);

struct function parse_function(void *ast);
char *print_expr_tree(struct expr *e);
struct expr *parse_antlr_tree(void *ast);
void print_tree_types(void *ast);

////////////////////////////////////////////////////////////
// struct expr
////////////////////////////////////////////////////////////

struct expr *expr_new();
struct expr *expr_clone(struct expr *other);

#define expr_free(e) (free(e), e = NULL)

////////////////////////////////////////////////////////////
// struct env_node
////////////////////////////////////////////////////////////

struct env_node *env_new();
struct env_node *env_new_with(char *name, struct expr *expr, struct env_node *next);
void env_free(struct env_node *first);

#define env_free_node(node) (free(node), node = NULL)

////////////////////////////////////////////////////////////
// struct union_node
////////////////////////////////////////////////////////////

struct union_node *union_new();
struct union_node *union_new_with(struct expr *e, struct union_node *next);
struct union_node *union_union(struct union_node *first, struct union_node *second);
struct union_node *union_add(struct union_node *first, struct expr *e);
void union_free(struct union_node *first);
struct union_node *union_flatten(struct union_node *first);
void union_sort(struct union_node **head);
struct union_node *union_objects_to_extents(struct union_node *head);
struct union_node *sorted_union_merge_extents(struct union_node *head);

#define union_free_node(node) (free(node), node = NULL)

////////////////////////////////////////////////////////////
// struct footprint_node
////////////////////////////////////////////////////////////

struct footprint_node *footprint_node_new();
struct footprint_node *footprint_node_new_with(char *name, char *arg_names[6], enum footprint_direction direction, struct union_node *exprs, struct footprint_node *next);
void footprint_free(struct footprint_node *node);
struct union_node *eval_footprint_with(struct footprint_node *footprint, struct env_node *defined_functions, struct uniqtype *func, long int arg_values[6]);
struct footprint_node *get_footprints_for(struct footprint_node *footprints, const char *name);
struct footprint_node *parse_footprints_from_file(const char *filename, struct env_node **output_env);
struct union_node *eval_footprints_for(struct footprint_node *footprints, struct env_node *defined_functions, const char *name, struct uniqtype *func, long int arg_values[6]);
char *print_footprint_extents(struct footprint_node *fp, struct union_node *extents);
struct footprint_node *new_from_subprogram_DIE(void *subprogram, struct footprint_node *next);

#define footprint_node_free(node) (free(node), node = NULL)
 
#endif


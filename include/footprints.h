#ifndef FOOTPRINTS_H_
#define FOOTPRINTS_H_

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include <antlr3.h>
#include <antlr3defs.h>
#include <dwarfidl/dwarfidlSimpleCLexer.h>
#include <dwarfidl/dwarfidlSimpleCParser.h>
#include <liballocs.h>

#include "uniqtype.h"

////////////////////////////////////////////////////////////
// structs
////////////////////////////////////////////////////////////

struct expr;

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
	 BIN_MEMBER
};

static const char *binary_ops_str[] = {
	 ">",
	 "<",
	 ">=",
	 "<=",
	 "==",
	 "!=",
	 "and",
	 "or",
	 "+",
	 "-",
	 "*",
	 "/",
	 "%",
	 "<<",
	 ">>",
	 "&",
	 "|",
	 "^",
	 "."
};

enum unary_ops {
	 UN_NOT,
	 UN_NEG,
	 UN_BITNOT,
	 UN_SIZEOF
};

static const char *unary_ops_str[] = {
	 "not",
	 "-",
	 "~",
	 "sizeof"
};

enum subscript_methods {
	 SUBSCRIPT_DIRECT_BYTES,
	 SUBSCRIPT_DEREF_BYTES,
	 SUBSCRIPT_DEREF_SIZES
};

static const char *subscript_methods_str[] = {
	 "SUBSCRIPT_DIRECT_BYTES",
	 "SUBSCRIPT_DEREF_BYTES",
	 "SUBSCRIPT_DEREF_SIZES"
};

enum expr_types {
	 EXPR_BINARY,
	 EXPR_UNARY,
	 EXPR_FOR,
	 EXPR_IF,
	 EXPR_SUBSCRIPT,
	 EXPR_EXTENT,
	 EXPR_UNION,
	 EXPR_OBJECT,
	 EXPR_IDENT,
	 EXPR_VALUE
};

static const char *expr_types_str[] = {
	 "EXPR_BINARY",
	 "EXPR_UNARY",
	 "EXPR_FOR",
	 "EXPR_IF",
	 "EXPR_SUBSCRIPT",
	 "EXPR_EXTENT",
	 "EXPR_UNION",
	 "EXPR_OBJECT",
	 "EXPR_IDENT",
	 "EXPR_VALUE"
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
};

struct env_node {
	 char *name;
	 struct object value;
	 struct env_node *next;
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
		  char *ident;
		  int value;
	 };
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
int eval_to_value(struct expr *e, struct env_node *env);
char *eval_to_ident(struct expr *e, struct env_node *env);
struct object eval_to_object(struct expr *e, struct env_node *env);
struct expr *construct_value(int value);
struct expr *construct_object(struct object value);
struct expr *eval_binary_op(struct expr* e, struct env_node *env); 
char *new_ident_not_in(struct env_node *env, char *suffix);
char *_find_ident_not_in(struct env_node *env, char *suffix, size_t length);
_Bool _ident_in(struct env_node *env, char *ident);
struct expr *eval_unary_op(struct expr* e, struct env_node *env);
struct expr *eval_for_loop(struct expr *e, struct env_node *env);
struct expr *eval_if_cond(struct expr *e, struct env_node *env);
struct expr *eval_subscript(struct expr *e, struct env_node *env);
struct object lookup_in_object(struct object *context, char *ident);
struct object lookup_in_env(struct env_node *env, char *ident);
struct expr *eval_ident(struct expr *e, struct env_node *env);
struct expr *eval_union(struct expr *e, struct env_node *env);

char *print_expr_tree(struct expr *e);
struct expr *parse_antlr_tree(ANTLR3_BASE_TREE *ast);
void print_tree_types(ANTLR3_BASE_TREE *ast);

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
struct env_node *env_new_with(char *name, struct object value, struct env_node *next);
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
 
#endif


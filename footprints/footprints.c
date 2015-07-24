#define _GNU_SOURCE

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include <dwarfidl/parser_includes.h>
#include "liballocs.h"
#include "footprints.h"

const char *binary_ops_str[] = {
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
	 ".",
	 "called with"
};

const char *unary_ops_str[] = {
	 "not",
	 "-",
	 "~",
	 "sizeof"
};

const char *subscript_methods_str[] = {
	 "SUBSCRIPT_DIRECT_BYTES",
	 "SUBSCRIPT_DEREF_BYTES",
	 "SUBSCRIPT_DEREF_SIZES"
};

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

const char *footprint_direction_str[] = {
	 "read",
	 "write",
	 "readwrite"
};

////////////////////////////////////////////////////////////
// evaluator
////////////////////////////////////////////////////////////

struct expr *eval_footprint_expr(struct expr* e, struct env_node *env) {
	 assert(e);
	 fprintf(stderr, "== eval_footprint_expr called with expr = %s (type = %s), env = ", print_expr_tree(e), expr_types_str[e->type]);
	 struct env_node *current = env;
	 while (current != NULL) {
		  fprintf(stderr, "%s%s", current->name, (current->next == NULL ? "" : ", "));
		  current = current->next;
	 }
	 fprintf(stderr, "\n");
	 switch (e->type) {
	 case EXPR_VOID:
	 case EXPR_VALUE:
	 case EXPR_EXTENT:
	 case EXPR_OBJECT:
		  return e;
		  break;
	 case EXPR_FOR: {
		  return eval_for_loop(e, env);
	 } break;
	 case EXPR_IF: {
		  return eval_if_cond(e, env);
	 } break;
	 case EXPR_BINARY: {
		  return eval_binary_op(e, env);
	 } break;
	 case EXPR_UNARY: {
		  return eval_binary_op(e, env);
	 } break;
	 case EXPR_IDENT: {
		  return eval_ident(e, env);
	 } break;
	 case EXPR_SUBSCRIPT: {
		  return eval_subscript(e, env);
	 } break;
	 case EXPR_UNION: {
		  return eval_union(e, env);
	 } break;
	 default:
		  assert(false);
	 }
}

int object_to_value(struct uniqtype *type, void *addr) {
/*	 if (type == &__uniqtype_int$16) {
		  return *(int16_t*)addr;
		  } else*/

     if (type == &__uniqtype__int$32) {
		  return *(int32_t*)addr;
	 } else if (type == &__uniqtype__int$64) {
		  return *(int64_t*)addr;
/*} else if (type == &__uniqtype__uint$16) {
  return *(uint16_t*)addr;*/
	 } else if (type == &__uniqtype__uint$32) {
		  return *(uint32_t*)addr;
	 } else if (type == &__uniqtype__uint$64) {
		  return *(uint64_t*)addr;
	 } else if (type == &__uniqtype__signed_char$8) {
		  return *(int8_t*)addr;
	 } else if (type == &__uniqtype__unsigned_char$8) {
		  return *(uint8_t*)addr;
	 } else {
		  assert(false);
	 }
}

int64_t eval_to_value(struct expr *e, struct env_node *env) {
	 struct expr *result = eval_footprint_expr(e, env);
	 if (result->type == EXPR_OBJECT) {
		  return object_to_value(result->object.type, result->object.addr);
	 } else {
		  assert(result->type == EXPR_VALUE);
		  return result->value;
	 }
}

char *eval_to_ident(struct expr *e, struct env_node *env) {
	 struct expr *result = eval_footprint_expr(e, env);
	 assert(result->type == EXPR_IDENT);
	 return result->ident;
}

struct object eval_to_object(struct expr *e, struct env_node *env) {
	 struct expr *result = eval_footprint_expr(e, env);
	 assert(result->type == EXPR_OBJECT);
	 return result->object;
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

struct expr *eval_binary_op(struct expr* e, struct env_node *env) {
	 assert(e->type == EXPR_BINARY);
	 switch (e->binary_op.op) {
	 case BIN_GT: {
		  int64_t left = eval_to_value(e->binary_op.left, env);
		  int64_t right = eval_to_value(e->binary_op.right, env);
		  return construct_value(left > right ? 1 : 0);
	 } break;	  
	 case BIN_LT: {
		  int64_t left = eval_to_value(e->binary_op.left, env);
		  int64_t right = eval_to_value(e->binary_op.right, env);
		  return construct_value(left < right ? 1 : 0);
		  } break;
	 case BIN_GTE: {
		  int64_t left = eval_to_value(e->binary_op.left, env);
		  int64_t right = eval_to_value(e->binary_op.right, env);
		  return construct_value(left >= right ? 1 : 0);
		  } break;
	 case BIN_LTE: {
		  int64_t left = eval_to_value(e->binary_op.left, env);
		  int64_t right = eval_to_value(e->binary_op.right, env);
		  return construct_value(left <= right ? 1 : 0);
		  } break;
	 case BIN_EQ: {
		  int64_t left = eval_to_value(e->binary_op.left, env);
		  int64_t right = eval_to_value(e->binary_op.right, env);
		  return construct_value(left == right ? 1 : 0);
		  } break;
	 case BIN_NE: {
		  int64_t left = eval_to_value(e->binary_op.left, env);
		  int64_t right = eval_to_value(e->binary_op.right, env);
		  return construct_value(left != right ? 1 : 0);
		  } break;
	 case BIN_AND: {
		  int64_t left = eval_to_value(e->binary_op.left, env);
		  int64_t right = eval_to_value(e->binary_op.right, env);
		  return construct_value(!!left && !!right ? 1 : 0);
		  } break;
	 case BIN_OR: {
		  int64_t left = eval_to_value(e->binary_op.left, env);
		  int64_t right = eval_to_value(e->binary_op.right, env);
		  return construct_value(!!left || !!right ? 1 : 0);
		  } break;
	 case BIN_ADD: {
		  int64_t left = eval_to_value(e->binary_op.left, env);
		  int64_t right = eval_to_value(e->binary_op.right, env);
		  return construct_value(left + right);
		  } break;
	 case BIN_SUB: {
		  int64_t left = eval_to_value(e->binary_op.left, env);
		  int64_t right = eval_to_value(e->binary_op.right, env);
		  return construct_value(left - right);
		  } break;
	 case BIN_MUL: {
		  int64_t left = eval_to_value(e->binary_op.left, env);
		  int64_t right = eval_to_value(e->binary_op.right, env);
		  return construct_value(left * right);
		  } break;
	 case BIN_DIV: {
		  int64_t left = eval_to_value(e->binary_op.left, env);
		  int64_t right = eval_to_value(e->binary_op.right, env);
		  return construct_value(left / right);
		  } break;
	 case BIN_MOD: {
		  int64_t left = eval_to_value(e->binary_op.left, env);
		  int64_t right = eval_to_value(e->binary_op.right, env);
		  return construct_value(left % right);
		  } break;
	 case BIN_SHL: {
		  int64_t left = eval_to_value(e->binary_op.left, env);
		  int64_t right = eval_to_value(e->binary_op.right, env);
		  return construct_value(left << right);
		  } break;
	 case BIN_SHR: {
		  int64_t left = eval_to_value(e->binary_op.left, env);
		  int64_t right = eval_to_value(e->binary_op.right, env);
		  return construct_value(left >> right);
		  } break;
	 case BIN_BITAND: {
		  int64_t left = eval_to_value(e->binary_op.left, env);
		  int64_t right = eval_to_value(e->binary_op.right, env);
		  return construct_value(left & right);
		  } break;
	 case BIN_BITOR: {
		  int64_t left = eval_to_value(e->binary_op.left, env);
		  int64_t right = eval_to_value(e->binary_op.right, env);
		  return construct_value(left | right);
		  } break;
	 case BIN_BITXOR: {
		  int64_t left = eval_to_value(e->binary_op.left, env);
		  int64_t right = eval_to_value(e->binary_op.right, env);
		  return construct_value(left ^ right);
		  } break;
	 case BIN_MEMBER: {
		  // if left is union:
		  //     return eval(x.right_ident for x in left_union)
		  // else:
		  //     return lookup(left_obj, right_ident)
		  assert(e->binary_op.right->type == EXPR_IDENT);
		  struct expr *left = eval_footprint_expr(e->binary_op.left, env);
		  if (left->type == EXPR_UNION) {
			   char *loop_var_name = new_ident_not_in(env, "loop_var");
			   
			   struct expr *loop_var_ident = expr_new();
			   loop_var_ident->type = EXPR_IDENT;
			   loop_var_ident->ident = loop_var_name;
			   
			   struct expr *loop_body = expr_new();
			   memcpy(loop_body, e, sizeof(struct expr));
			   loop_body->binary_op.left = loop_var_ident;

			   struct expr *loop = expr_new();
			   loop->type = EXPR_FOR;
			   loop->for_loop.body = loop_body;
			   loop->for_loop.ident = loop_var_name;
			   loop->for_loop.over = left;
			   
			   return eval_footprint_expr(loop, env);
		  } else if (left->type == EXPR_OBJECT) {
			   return construct_object(lookup_in_object(&left->object, e->binary_op.right->ident));
		  } else {
			   assert(false);
		  }
	 } break;
	 default:
		  assert(false);
		  break;
	 }
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


char *new_ident_not_in(struct env_node *env, char *suffix) {
	 size_t length = strlen(suffix);
	 char *copy = malloc(length+1); // + \0
	 strcpy(copy, suffix);
	 return _find_ident_not_in(env, copy, length);
}

char *_find_ident_not_in(struct env_node *env, char *suffix, size_t length) {
	 if (!_ident_in(env, suffix)) {
		  return suffix;
	 } else {
		  // copy = _suffix
		  char *copy = malloc(length+2); // + 1 + \0
		  copy[0] = '_';
		  strcpy(copy+1, suffix);
		  // we own suffix because this is only called behind new_ident_not_in
		  free(suffix);
		  return _find_ident_not_in(env, copy, length+1);
	 }
}

_Bool _ident_in(struct env_node *env, char *ident) {
	 struct env_node *current = env;
	 while (current != NULL) {
		  if (current->name == ident) {
			   return true;
		  }
		  current = current->next;
	 }
	 return false;
}


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

struct expr *eval_for_loop(struct expr *e, struct env_node *env) {
	 // f(x) for x in xs -> union(f(x1), f(x2), ... f(xn))
	 assert(e->type == EXPR_FOR);
	 
	 struct expr *over = eval_footprint_expr(e->for_loop.over, env);
	 assert(over->type == EXPR_UNION);
	 
	 struct union_node *tail = NULL;
	 struct union_node *current = over->unioned;
	 while (current != NULL) {
		  struct env_node *head_env = env_new();
		  head_env->name = e->for_loop.ident;
		  head_env->expr = eval_footprint_expr(current->expr, env);
		  head_env->next = env;
		  struct union_node *head = union_new();
		  head->expr = eval_footprint_expr(e->for_loop.body, head_env);
		  head->next = tail;
		  tail = head;
		  current = current->next;
	 }

	 struct expr *result = expr_new();
	 result->type = EXPR_UNION;
	 result->unioned = tail;
	 	 
	 return result;
}

struct expr *eval_if_cond(struct expr *e, struct env_node *env) {
	 assert(e->type == EXPR_IF);
	 if (eval_to_value(e->if_cond.cond, env)) {
		  return eval_footprint_expr(e->if_cond.then, env);
	 } else {
		  return eval_footprint_expr(e->if_cond.otherwise, env);
	 }
}

struct object deref_object(struct object ptr) {
	 assert(UNIQTYPE_IS_POINTER_TYPE(ptr.type));
	 struct object obj;
	 obj.type = UNIQTYPE_POINTEE_TYPE(ptr.type);
	 // aaaaaaaa scary
	 obj.addr = *(void**)ptr.addr;
	 return obj;
}

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

struct expr *construct_void() {
	 struct expr *result = expr_new();
	 result->type = EXPR_VOID;
	 return result;
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

struct expr *extent_from_object(struct object obj) {
	 assert(UNIQTYPE_HAS_KNOWN_LENGTH(obj.type));
	 size_t size = obj.type->pos_maxoff;
	 return construct_extent((unsigned long) obj.addr, size);
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

struct object lookup_in_object(struct object *context, char *ident) {
	 assert(context != NULL);
	 assert(context->type != NULL);
	 struct object obj;
	 size_t i;
	 for (i = 0; i < context->type->nmemb; i++) {
		  if (strcmp(ident, context->type->subobj_names[i]) == 0) {
			   obj.type = context->type->contained[i].ptr;
			   obj.addr = (void*) context->addr + context->type->contained[i].offset;
			   return obj;
		  }
	 }

	 // not found
	 assert(false);
}

struct object lookup_in_env(struct env_node *env, char *ident) {
	 struct env_node *current = env;
	 while (current != NULL) {
		  if (strcmp(ident, current->name) == 0) {
			   fprintf(stderr, "looked up %s and found %p\n", ident, (void*) object_to_value(current->value.type, current->value.addr));
			   return current->value;
		  }
		  current = current->next;
	 }
	 
	 // not found
	 assert(false);
}

struct expr *eval_ident(struct expr *e, struct env_node *env) {
	 assert(e->type == EXPR_IDENT);
	 return construct_object(lookup_in_env(env, e->ident));
}

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



////////////////////////////////////////////////////////////
// struct env_node
////////////////////////////////////////////////////////////

struct env_node *env_new() {
	 struct env_node *result = malloc(sizeof(struct env_node));
	 memset(result, 0, sizeof(struct env_node));
	 return result;
}

struct env_node *env_new_with(char *name, struct object value, struct env_node *next) {
	 struct env_node *result = env_new();
	 result->name = name;
	 result->value = value;
	 result->next = next;
	 return result;
}


void env_free(struct env_node *first) {
	 struct env_node *current = first;
	 struct env_node *next;
	 while (current != NULL) {
		  next = current->next;
		  union_free_node(current);
		  current = next;
	 }
}

////////////////////////////////////////////////////////////
// struct union_node
////////////////////////////////////////////////////////////

struct union_node *union_new() {
	 struct union_node *result = malloc(sizeof(struct union_node));
	 memset(result, 0, sizeof(struct union_node));
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

void union_free(struct union_node *first) {
	 struct union_node *current = first;
	 struct union_node *next;
	 while (current != NULL) {
		  next = current->next;
		  union_free_node(current);
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

/* struct union_node *union_objects_to_bytes(struct union_node *head) { */
/* 	 struct union_node *tail = NULL; */
/* 	 struct union_node *current = head; */
/* 	 struct union_node *next = NULL; */
/* 	 while (current != NULL) { */
/* 		  next = current->next; */
/* 		  if (current->expr->type == EXPR_EXTENT) { */
/* 			   current->next = tail; */
/* 			   tail = current; */
/* 			   current = next; */
/* 		  } else { */
/* 			   assert(current->expr->type == EXPR_OBJECT); */
/* 			   assert(UNIQTYPE_HAS_KNOWN_LENGTH(current->expr->object.type)); */
/* 			   if (current->expr->object.type->pos_maxoff == 1) { */
/* 					current->next = tail; */
/* 					tail = current; */
/* 			   } else { */
/* 					/\* struct union_node *bytes = union_new_with(); bytes_union_from_object(current->expr->object); *\/ */
/* 					/\* tail = union_union(bytes, tail); *\/ */
/* 					tail = union_new_with(extent_from_object(current->expr->object), tail); */
/* 			   } */
/* 		  } */
		  
/* 		  current = next; */
/* 	 } */
/* 	 return tail; */
/* } */

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
			   //fprintf(stderr, "merging n=%p base=%p onto n=%p base=%p\n", next->expr->extent.length, next->expr->extent.base, length, base);
			   length = (next->expr->extent.base + next->expr->extent.length) - base;
			   next = next->next;
		  }

		  if (next != NULL) {
			   //fprintf(stderr, "NOT merging n=%p base=%p onto n=%p base=%p\n", next->expr->extent.length, next->expr->extent.base, length, base);
		  }

		  extents = union_new_with(construct_extent(base, length), extents);
		  current = next;
	 }

	 return extents;
}

	 
char *print_expr_tree(struct expr *e) {
	 if (e == NULL) return "(null)";
	 char *body = NULL;
	 switch (e->type) {
	 case EXPR_VOID: {
		  asprintf(&body, "(void)");
	 } break;
	 case EXPR_BINARY: {
		  asprintf(&body, "(%s %s %s)", print_expr_tree(e->binary_op.left), binary_ops_str[e->binary_op.op], print_expr_tree(e->binary_op.right));
	 } break;
	 case EXPR_UNARY: {
		  asprintf(&body, "(%s %s)", unary_ops_str[e->unary_op.op], print_expr_tree(e->unary_op.arg));
	 } break;
	 case EXPR_FOR: {
		  asprintf(&body, "(%s for %s in %s)", print_expr_tree(e->for_loop.body), e->for_loop.ident, print_expr_tree(e->for_loop.over));
	 } break;
	 case EXPR_IF: {
		  asprintf(&body, "(if %s then %s else %s)", print_expr_tree(e->if_cond.cond), print_expr_tree(e->if_cond.then), print_expr_tree(e->if_cond.otherwise));
	 } break;
	 case EXPR_SUBSCRIPT: {
		  char *open_bracket;
		  char *close_bracket;
		  switch (e->subscript.method) {
		  case SUBSCRIPT_DIRECT_BYTES:
			   open_bracket = "{";
			   close_bracket = "}";
			   break;
		  case SUBSCRIPT_DEREF_BYTES:
			   open_bracket = "[{";
			   close_bracket = "}]";
			   break;
		  case SUBSCRIPT_DEREF_SIZES:
			   open_bracket = "[";
			   close_bracket = "]";
			   break;
		  default:
			   assert(false);
		  }
		  if (e->subscript.to) {
			   asprintf(&body, "(subscript %s %s%s .. %s%s)", print_expr_tree(e->subscript.target), open_bracket, print_expr_tree(e->subscript.from), print_expr_tree(e->subscript.to), close_bracket);
		  } else {
			   asprintf(&body, "(subscript %s %s%s%s)", print_expr_tree(e->subscript.target), open_bracket, print_expr_tree(e->subscript.from), close_bracket);
		  }
	 } break;
	 case EXPR_EXTENT: {
		  asprintf(&body, "(extent base = %lx, length = %lx)", e->extent.base, e->extent.length);
	 } break;
	 case EXPR_UNION: {
		  int n_nodes = 0;
		  struct union_node *current = e->unioned;
		  while (current != NULL) {
			   n_nodes++;
			   current = current->next;
		  }

		  char *union_str[n_nodes];
		  
		  int total_strlen = n_nodes; // n-1 spaces and \0
		  
		  current = e->unioned;
		  int i = 0;
		  while (current != NULL) {
			   union_str[i] = print_expr_tree(current->expr);
			   total_strlen += strlen(union_str[i]);
			   i++;
			   current = current->next;
		  }

		  char *union_body = malloc(total_strlen);
		  char *cur_char = union_body;

		  for (i = 0; i < n_nodes; i++) {
			   if (i > 0) {
					cur_char = stpcpy(cur_char, " ");
			   }
			   cur_char = stpcpy(cur_char, union_str[i]);
		  }

		  asprintf(&body, "(union %s)", union_body);
	 } break;
	 case EXPR_OBJECT: {
		  asprintf(&body, "(object @%p of type %s)", e->object.addr, e->object.type->name);
	 } break;
	 case EXPR_IDENT: {
		  asprintf(&body, "%s", e->ident);
	 } break;
	 case EXPR_VALUE: {
		  asprintf(&body, "%ld", e->value);
	 } break;
	 default:
		  assert(false);
	 }
	 assert(body != NULL);
	 return body;
}

/* Stolen from libantlr3cxx and very roughly converted to C */

#define GET_TEXT(node) (node)->getText((node))
#define TO_STRING(node) (node)->toString((node))
#define GET_TYPE(node) (node)->getType((node))
#define GET_PARENT(node) (node)->getParent((node))
#define GET_CHILD_COUNT(node) (node)->getChildCount((node))
#define TO_STRING_TREE(node) (node)->toStringTree((node))
static inline ANTLR3_BASE_TREE *get_child_(ANTLR3_BASE_TREE *n, int i)
{
	 ANTLR3_BASE_TREE *child = (ANTLR3_BASE_TREE *)(n->getChild(n, i));
	if (child) ((ANTLR3_COMMON_TREE*)(child->super))->parent = (ANTLR3_COMMON_TREE*)(n->super);
	return child;
}
#define GET_CHILD(node, i) (get_child_((node), (i)))
#define TOKEN(tokname) tokname
#define GET_FACTORY(node) (((ANTLR3_BASE_TREE*) (node)->super)->factory)
#define ASSIGN_AS_COND(name, value) \
	(((name) = (value)) == (name))
#define FOR_ALL_CHILDREN(t) unsigned i = 0; \
	FOR_BODY(t)	
#define FOR_REMAINING_CHILDREN(t) unsigned i = next_child_to_bind; \
	FOR_BODY(t)
#define FOR_BODY(t) \
	 ANTLR3_BASE_TREE *__tree_head_pointer = (ANTLR3_BASE_TREE *)(t); /* because our tree may well alias 'n' */ \
	unsigned childcount; \
	const char *text __attribute__((unused)) = 0; \
	ANTLR3_BASE_TREE *n = 0; \
	for (childcount = GET_CHILD_COUNT(__tree_head_pointer), \
			  n = ((childcount > 0) ? (ANTLR3_BASE_TREE*)(GET_CHILD(__tree_head_pointer, 0)) : 0), \
		text = (n != 0 && ((GET_TEXT(n)) != 0)) ? CCP(GET_TEXT(n)) : "(null)"; \
		 i < childcount && (n = (ANTLR3_BASE_TREE*)(GET_CHILD(__tree_head_pointer, i)), true) && \
		(( text = ((n != 0 && ((GET_TEXT(n)) != 0)) ? CCP(GET_TEXT(n)) : "(null)") ), true); \
	i++)
#define CHECK_TOKEN(node, token, tokenname) \
	 assert(GET_TYPE(node) == token);
#define INIT int next_child_to_bind __attribute__(( unused )) = 0 
#define BIND2(node, name) ANTLR3_BASE_TREE *(name) __attribute__((unused)) = (ANTLR3_BASE_TREE*)(GET_CHILD(node, next_child_to_bind++));
#define BIND3(node, name, token) ANTLR3_BASE_TREE *(name) __attribute__((unused)) = (ANTLR3_BASE_TREE*)(GET_CHILD(node, next_child_to_bind++)); \
	 assert((name) != 0); \
	CHECK_TOKEN(name, token, #token) \

#define SELECT_NOT(token) if (GET_TYPE(n) == (token)) continue
#define SELECT_ONLY(token) if (GET_TYPE(n) != (token)) continue
#define CCP(p) ((p) ? (char*)((p->chars)) : "(no text)")

/* end plagiarism */

char *parse_ident(ANTLR3_BASE_TREE *ast) {
	 assert(ast);
	 assert(GET_TYPE(ast) == IDENTS);
	 size_t n_children = GET_CHILD_COUNT(ast);
	 char *child_str[n_children];
	 size_t total_strlen = n_children; // n-1 spaces and \0
	 size_t i;
	 for (i = 0; i < n_children; i++) {
		  child_str[i] = CCP(GET_TEXT(GET_CHILD(ast, i)));
		  total_strlen += strlen(child_str[i]);
	 }

	 char *ident = malloc(total_strlen);
	 char *cur_char = ident;
	 for (i = 0; i < n_children; i++) {
		  if (i > 0) {
			   cur_char = stpcpy(cur_char, " ");
		  }
		  cur_char = stpcpy(cur_char, child_str[i]);
	 }

	 return ident;
}

int64_t parse_int(ANTLR3_BASE_TREE *ast) {
	 assert(ast);
	 assert(GET_TYPE(ast) == INT);
	 const char * s = CCP(GET_TEXT(ast));
	 int64_t result = 0;
	 int64_t n = sscanf(s, "0x%lx", &result);
	 if (n == 1) {
		  return result;
	 } else {
		  n = sscanf(s, "0%lo", &result);
		  if (n == 1) {
			   return result;
		  } else {
			   n = sscanf(s, "%ld", &result);
			   if (n == 1) {
					return result;
			   } else {
					assert(false);
			   }
		  }
	 }
	 return 0;
}

struct expr *parse_antlr_tree(void *ptr) {
	 ANTLR3_BASE_TREE *ast = (ANTLR3_BASE_TREE*)ptr;
	 assert(ast);
	 struct expr *e = expr_new();
	 switch (GET_TYPE(ast)) {
	 case FP_GT:
	 case FP_LT:
	 case FP_GTE:
	 case FP_LTE:
	 case FP_EQ:
	 case FP_NE:
	 case FP_AND:
	 case FP_OR:
	 case FP_ADD:
	 case FP_SUB:
	 case FP_MUL:
	 case FP_DIV:
	 case FP_MOD:
	 case FP_SHL:
	 case FP_SHR:
	 case FP_BITAND:
	 case FP_BITOR:
	 case FP_BITXOR:
	 case FP_MEMBER:
		  e->type = EXPR_BINARY;
		  break;
	 case FP_NOT:
	 case FP_NEG:
	 case FP_BITNOT:
	 case FP_SIZEOF:
		  e->type = EXPR_UNARY;
		  break;
	 case FP_FOR:
		  e->type = EXPR_FOR;
		  break;
	 case FP_IF:
		  e->type = EXPR_IF;
		  break;
	 case FP_SUBSCRIPT:
		  e->type = EXPR_SUBSCRIPT;
		  break;
	 case IDENTS:
		  e->type = EXPR_IDENT;
		  break;
	 case INT:
		  e->type = EXPR_VALUE;
		  break;
	 case FP_UNION:
		  e->type = EXPR_UNION;
		  break;
	 case FP_VOID:
		  e->type = EXPR_VOID;
		  break;
	 default:
		  assert(false);
	 }

	 switch (e->type) {
	 case EXPR_VOID: {
		  // nothing further to do
	 } break;
	 case EXPR_BINARY: {
		  assert(GET_CHILD_COUNT(ast) == 2);
		  switch (GET_TYPE(ast)) {
		  case FP_GT:
			   e->binary_op.op = BIN_GT;
			   break;
		  case FP_LT:
			   e->binary_op.op = BIN_LT;
			   break;
		  case FP_GTE:
			   e->binary_op.op = BIN_GTE;
			   break;
		  case FP_LTE:
			   e->binary_op.op = BIN_LTE;
			   break;
		  case FP_EQ:
			   e->binary_op.op = BIN_EQ;
			   break;
		  case FP_NE:
			   e->binary_op.op = BIN_NE;
			   break;
		  case FP_AND:
			   e->binary_op.op = BIN_AND;
			   break;
		  case FP_OR:
			   e->binary_op.op = BIN_OR;
			   break;
		  case FP_ADD:
			   e->binary_op.op = BIN_ADD;
			   break;
		  case FP_SUB:
			   e->binary_op.op = BIN_SUB;
			   break;
		  case FP_MUL:
			   e->binary_op.op = BIN_MUL;
			   break;
		  case FP_DIV:
			   e->binary_op.op = BIN_DIV;
			   break;
		  case FP_MOD:
			   e->binary_op.op = BIN_MOD;
			   break;
		  case FP_SHL:
			   e->binary_op.op = BIN_SHL;
			   break;
		  case FP_SHR:
			   e->binary_op.op = BIN_SHR;
			   break;
		  case FP_BITAND:
			   e->binary_op.op = BIN_BITAND;
			   break;
		  case FP_BITOR:
			   e->binary_op.op = BIN_BITOR;
			   break;
		  case FP_BITXOR:
			   e->binary_op.op = BIN_BITXOR;
			   break;
		  case FP_MEMBER:
			   e->binary_op.op = BIN_MEMBER;
			   break;
		  default:
			   assert(false);
		  }
		  
		  e->binary_op.left = parse_antlr_tree(GET_CHILD(ast, 0));
		  e->binary_op.right = parse_antlr_tree(GET_CHILD(ast, 1));
	 } break;
	 case EXPR_UNARY: {
		  assert(GET_CHILD_COUNT(ast) == 1);
		  switch (GET_TYPE(ast)) {
		  case FP_NOT:
			   e->unary_op.op = UN_NOT;
			   break;
		  case FP_NEG:
			   e->unary_op.op = UN_NEG;
			   break;
		  case FP_BITNOT:
			   e->unary_op.op = UN_BITNOT;
			   break;
		  case FP_SIZEOF:
			   e->unary_op.op = UN_SIZEOF;
			   break;
		  default:
			   assert(false);
		  }

		  e->unary_op.arg = parse_antlr_tree(GET_CHILD(ast, 0));
	 } break;
	 case EXPR_FOR: {
		  assert(GET_CHILD_COUNT(ast) == 3);
		  e->for_loop.body = parse_antlr_tree(GET_CHILD(ast, 0));
		  e->for_loop.ident = parse_ident(GET_CHILD(ast, 1));
		  e->for_loop.over = parse_antlr_tree(GET_CHILD(ast, 2));
	 } break;
	 case EXPR_IF: {
		  assert(GET_CHILD_COUNT(ast) == 3);
		  e->if_cond.cond = parse_antlr_tree(GET_CHILD(ast, 0));
		  e->if_cond.then = parse_antlr_tree(GET_CHILD(ast, 1));
		  e->if_cond.otherwise = parse_antlr_tree(GET_CHILD(ast, 2));
	 } break;
	 case EXPR_SUBSCRIPT: {
		  assert(GET_CHILD_COUNT(ast) == 3 || GET_CHILD_COUNT(ast) == 4);
		  switch (GET_TYPE(GET_CHILD(ast, 0))) {
		  case FP_DEREFBYTES:
			   e->subscript.method = SUBSCRIPT_DEREF_BYTES;
			   break;
		  case FP_DEREFSIZES:
			   e->subscript.method = SUBSCRIPT_DEREF_SIZES;
			   break;
		  case FP_DIRECTBYTES:
			   e->subscript.method = SUBSCRIPT_DIRECT_BYTES;
			   break;
		  default:
			   assert(false);
		  }
		  e->subscript.target = parse_antlr_tree(GET_CHILD(ast, 1));

		  e->subscript.from = parse_antlr_tree(GET_CHILD(ast, 2));
		  if (GET_CHILD_COUNT(ast) > 3) {
			   e->subscript.to = parse_antlr_tree(GET_CHILD(ast, 3));
		  }
	 } break;
	 case EXPR_IDENT: {
		  assert(GET_CHILD_COUNT(ast) > 0);
		  e->ident = parse_ident(ast);
	 } break;
	 case EXPR_VALUE: {
		  assert(GET_CHILD_COUNT(ast) == 0);
		  e->value = parse_int(ast);
	 } break;
	 case EXPR_UNION: {
		  struct union_node *tail = NULL;
		  FOR_ALL_CHILDREN(ast) {
			   tail = union_new_with(parse_antlr_tree(n), tail);
		  }
		  e->unioned = tail;
	 } break;
	 default:
		  assert(false);
	 }
	 
	 return e;
}

void print_tree_types(void *ptr) {
	 ANTLR3_BASE_TREE *ast = (ANTLR3_BASE_TREE*)ptr;
	 fprintf(stderr, "(%d[%s] ", GET_TYPE(ast), CCP(GET_TEXT(ast)));
	 _Bool first = true;
	 FOR_ALL_CHILDREN(ast) {
		  if (first) {
			   first = false;
		  } else {
			   fprintf(stderr, " ");
		  }
		  print_tree_types(n);
	 }
	 fprintf(stderr, ")");
}

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

void footprint_free(struct footprint_node *head) {
	 struct footprint_node *current = head;
	 struct footprint_node *next = NULL;
	 while (current != NULL) {
		  next = current->next;
		  footprint_node_free(current);
		  current = next;
	 }
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

struct union_node *eval_footprint_with(struct footprint_node *footprint, struct uniqtype *func, long int arg_values[6]) {
	 struct env_node *env = NULL;
	 for (uint8_t i = 0; i < 6; i++) {
		  if (footprint->arg_names[i] == NULL) {
			   break;
		  } else {
			   struct object o;
			   o.type = func->contained[i+1].ptr;
			   o.addr = arg_values + i;
			   fprintf(stderr, "created arg %s with type %s and typed value 0x%lx from untyped 0x%lx\n", footprint->arg_names[i], o.type->name, object_to_value(o.type, o.addr), arg_values[i]);
			   env = env_new_with(footprint->arg_names[i], o, env);
		  }
	 }

	 struct expr *evaled = eval_footprint_expr(construct_union(footprint->exprs), env);
	 struct union_node *result;

	 if (evaled->type != EXPR_UNION) {
		  result = union_new_with(evaled, NULL);
	 } else {
		  result = evaled->unioned;
	 }

	 result = union_flatten(result);
	 result = _union_remove_type(result, EXPR_VOID);
	 result = union_objects_to_extents(result);
	 union_sort(&result);
	 result = sorted_union_merge_extents(result);
	 return result;
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

struct footprint_node *parse_footprints_from_file(char *filename) {
	 pANTLR3_INPUT_STREAM in_fileobj = antlr3FileStreamNew((uint8_t *) filename,
														   ANTLR3_ENC_UTF8);
	 if (!in_fileobj) {
		  perror("Could not open antlr3FileStream");
		  return NULL;
	 }
	 dwarfidlSimpleCLexer *lexer = dwarfidlSimpleCLexerNew(in_fileobj);
	 ANTLR3_COMMON_TOKEN_STREAM *tokenStream = antlr3CommonTokenStreamSourceNew(
		  ANTLR3_SIZE_HINT, TOKENSOURCE(lexer));
	 dwarfidlSimpleCParser *parser = dwarfidlSimpleCParserNew(tokenStream); 
	 ANTLR3_BASE_TREE *ast = parser->toplevel(parser).tree;

	 struct footprint_node *prints = NULL;

	 assert(GET_TYPE(ast) == DIES);

	 fprintf(stderr, "%s\n", TO_STRING_TREE(ast)->chars);

	 for (size_t i = 0; i < GET_CHILD_COUNT(ast); i++) {
		  ANTLR3_BASE_TREE *die = GET_CHILD(ast, i);
		  if (GET_TYPE(die) == DIE &&
			  GET_CHILD_COUNT(die) > 0 &&
			  GET_TYPE(GET_CHILD(die, 0)) == KEYWORD_TAG &&
			  strcmp(CCP(GET_TEXT(GET_CHILD(die, 0))), "subprogram") == 0) {
			   prints = new_from_subprogram_DIE(die, prints);
		  }
	 }

	 return prints;
}

struct footprint_node *new_from_subprogram_DIE(void *ptr, struct footprint_node *next) {
	 ANTLR3_BASE_TREE *subprogram = (ANTLR3_BASE_TREE*)ptr;
	 assert(subprogram);
	 assert(GET_TYPE(subprogram) == DIE);
	 assert(GET_CHILD_COUNT(subprogram) > 0);
	 ANTLR3_BASE_TREE *tag_node = GET_CHILD(subprogram, 0);
	 assert(GET_TYPE(tag_node) == KEYWORD_TAG);
	 assert(strcmp(CCP(GET_TEXT(tag_node)), "subprogram") == 0);
	 size_t n_arguments = 0;

	 struct footprint_node *node = footprint_node_new();
	 node->next = next;

	 struct union_node *exprs = NULL;
	 
	 for (size_t i = 0; i < GET_CHILD_COUNT(subprogram); i++) {
		  ANTLR3_BASE_TREE *child = GET_CHILD(subprogram, i);
		  if (GET_TYPE(child) == ATTRS) {
			   for (size_t j = 0; j < GET_CHILD_COUNT(child); j++) {
					ANTLR3_BASE_TREE *attr = GET_CHILD(child, j);
					if (GET_TYPE(attr) == ATTR &&
						GET_CHILD_COUNT(attr) == 2) {
						 ANTLR3_BASE_TREE *key = GET_CHILD(attr, 0);
						 ANTLR3_BASE_TREE *value = GET_CHILD(attr, 1);
						 if (GET_TYPE(key) == NAME) {
							  
							  assert(GET_TYPE(value) == IDENTS);
							  node->name = parse_ident(value);
							  
						 } else if (GET_TYPE(key) == FOOTPRINT) {
							  
							  assert(GET_TYPE(value) == FP_CLAUSES);
							  for (size_t k = 0; k < GET_CHILD_COUNT(value); k++) {

								   ANTLR3_BASE_TREE *clause = GET_CHILD(value, k);
								   assert(GET_TYPE(clause) == FP_CLAUSE);
								   switch (GET_TYPE(GET_CHILD(clause, 0))) {
								   case KEYWORD_R:
										node->direction = FOOTPRINT_READWRITE; // TODO FIXME HACK
										break;
								   case KEYWORD_W:
										node->direction = FOOTPRINT_READWRITE; // TODO FIXME HACK
										break;
								   case KEYWORD_RW:
										node->direction = FOOTPRINT_READWRITE;
										break;
								   default:
										assert(false);
								   }
								   exprs = union_new_with(parse_antlr_tree(GET_CHILD(clause, 1)), exprs);
							  }
							  
						 } else {
							  // something we don't care about
							  continue;
						 }
					} else {
						 continue;
					}
			   }
		  } else if (GET_TYPE(child) == CHILDREN) {
			   for (size_t j = 0; j < GET_CHILD_COUNT(child); j++) {
					ANTLR3_BASE_TREE *subdie = GET_CHILD(child, j);
					if (GET_TYPE(subdie) == DIE &&
						GET_CHILD_COUNT(subdie) > 0 &&
						GET_TYPE(GET_CHILD(subdie, 0)) == KEYWORD_TAG &&
						strcmp(CCP(GET_TEXT(GET_CHILD(subdie, 0))), "formal_parameter") == 0) {
						 // an argument!
						 _Bool have_name = false;

						 for (size_t k = 0; k < GET_CHILD_COUNT(subdie); k++) {
							  ANTLR3_BASE_TREE *sub_child = GET_CHILD(subdie, k);
							  if (GET_TYPE(sub_child) == ATTRS) {
								   for (size_t l = 0; l < GET_CHILD_COUNT(sub_child); l++) {
										ANTLR3_BASE_TREE *sub_attr = GET_CHILD(sub_child, l);
										if (GET_TYPE(sub_attr) == ATTR &&
											GET_CHILD_COUNT(sub_attr) == 2) {
											 ANTLR3_BASE_TREE *sub_key = GET_CHILD(sub_attr, 0);
											 ANTLR3_BASE_TREE *sub_value = GET_CHILD(sub_attr, 1);
											 if (GET_TYPE(sub_key) == NAME) {
												  assert(GET_TYPE(sub_value) == IDENTS);
												  node->arg_names[n_arguments] = parse_ident(sub_value);
												  have_name = true;
											 } else {
												  continue;
											 }
										} else {
											 continue;
										}
								   }
							  } else {
								   continue;
							  }
						 }
						 
						 if (!have_name) {
							  node->arg_names[n_arguments] = "(no name)";
						 }
						 n_arguments++;
					} else {
						 // something we don't care about
						 continue;
					}
			   }
		  } else {
			   continue;
		  }
	 }

	 node->exprs = exprs;
	 return node;
}

struct union_node *eval_footprint_for(struct footprint_node *footprints, char *name, struct uniqtype *func, long int arg_values[6]) {
	 struct footprint_node *fp = get_footprint_for(footprints, name);
	 if (fp != NULL) {
		  fprintf(stderr, "Evaling footprint for %s(0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx)\n", name, arg_values[0], arg_values[1], arg_values[2], arg_values[3], arg_values[4], arg_values[5]);
		  struct union_node *result = eval_footprint_with(fp, func, arg_values);
		  fprintf(stderr, "Result:\n%s\n", print_footprint_extents(fp, result));
		  return result;
	 } else {
		  return NULL;
	 }
}

char *print_footprint_extents(struct footprint_node *fp, struct union_node *extents) {
	 size_t n_nodes = 0;
	 struct union_node *current = extents;
	 while (current != NULL) {
		  n_nodes++;
		  current = current->next;
	 }
	 
	 char *union_str[n_nodes];
	 size_t total_strlen = n_nodes; // n-1 newlines and \0

	 const char *direction = footprint_direction_str[fp->direction];
	 
	 current = extents;
	 size_t i = 0;
	 while (current != NULL) {
		  assert(current->expr->type == EXPR_EXTENT);
		  asprintf(&(union_str[i]), "Allowed footprint: %s n=0x%lx base=0x%lx", direction, current->expr->extent.length, current->expr->extent.base);
		  assert(union_str[i]);
		  total_strlen += strlen(union_str[i]);
		  i++;
		  current = current->next;
	 }
	 
	 char *union_body = malloc(total_strlen);
	 char *cur_char = union_body;
	 
	 for (i = 0; i < n_nodes; i++) {
		  if (i > 0) {
			   cur_char = stpcpy(cur_char, "\n");
		  }
		  cur_char = stpcpy(cur_char, union_str[i]);
	 }
	 
	 return union_body;
}

#define _GNU_SOURCE

#include "footprints.h"

////////////////////////////////////////////////////////////
// evaluator
////////////////////////////////////////////////////////////

struct expr *eval_footprint_expr(struct expr* e, struct env_node *env) {
	 assert(e);
	 if (!env) {
		  env = env_new();
	 }
	 switch (e->type) {
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
	 case EXPR_VALUE: {
		  return e;
	 } break;
	 case EXPR_SUBSCRIPT: {
		  return eval_subscript(e, env);
	 } break;
	 case EXPR_EXTENT: {
		  return e;
	 } break;
	 case EXPR_UNION: {
		  return eval_union(e, env);
	 } break;
	 default:
		  assert(false);
	 }
}

int object_to_value(struct uniqtype *type, void *addr) {
	 if (type == &__uniqtype__int$16) {
		  return *(int16_t*)addr;
	 } else if (type == &__uniqtype__int$32) {
		  return *(int32_t*)addr;
	 } else if (type == &__uniqtype__int$64) {
		  return *(int64_t*)addr;
	 } else if (type == &__uniqtype__uint$16) {
		  return *(uint16_t*)addr;
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

int eval_to_value(struct expr *e, struct env_node *env) {
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

struct expr *construct_value(int value) {
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

struct expr *construct_extent(int base, int length) {
	 struct expr *result = expr_new();
	 result->type = EXPR_EXTENT;
	 result->extent.base = base;
	 result->extent.length = length;
	 return result;
}

struct expr *eval_binary_op(struct expr* e, struct env_node *env) {
	 assert(e->type == EXPR_BINARY);
	 switch (e->binary_op.op) {
	 case BIN_GT: {
		  int left = eval_to_value(e->binary_op.left, env);
		  int right = eval_to_value(e->binary_op.right, env);
		  return construct_value(left > right ? 1 : 0);
	 } break;	  
	 case BIN_LT: {
		  int left = eval_to_value(e->binary_op.left, env);
		  int right = eval_to_value(e->binary_op.right, env);
		  return construct_value(left < right ? 1 : 0);
		  } break;
	 case BIN_GTE: {
		  int left = eval_to_value(e->binary_op.left, env);
		  int right = eval_to_value(e->binary_op.right, env);
		  return construct_value(left >= right ? 1 : 0);
		  } break;
	 case BIN_LTE: {
		  int left = eval_to_value(e->binary_op.left, env);
		  int right = eval_to_value(e->binary_op.right, env);
		  return construct_value(left <= right ? 1 : 0);
		  } break;
	 case BIN_EQ: {
		  int left = eval_to_value(e->binary_op.left, env);
		  int right = eval_to_value(e->binary_op.right, env);
		  return construct_value(left == right ? 1 : 0);
		  } break;
	 case BIN_NE: {
		  int left = eval_to_value(e->binary_op.left, env);
		  int right = eval_to_value(e->binary_op.right, env);
		  return construct_value(left != right ? 1 : 0);
		  } break;
	 case BIN_AND: {
		  int left = eval_to_value(e->binary_op.left, env);
		  int right = eval_to_value(e->binary_op.right, env);
		  return construct_value(!!left && !!right ? 1 : 0);
		  } break;
	 case BIN_OR: {
		  int left = eval_to_value(e->binary_op.left, env);
		  int right = eval_to_value(e->binary_op.right, env);
		  return construct_value(!!left || !!right ? 1 : 0);
		  } break;
	 case BIN_ADD: {
		  int left = eval_to_value(e->binary_op.left, env);
		  int right = eval_to_value(e->binary_op.right, env);
		  return construct_value(left + right);
		  } break;
	 case BIN_SUB: {
		  int left = eval_to_value(e->binary_op.left, env);
		  int right = eval_to_value(e->binary_op.right, env);
		  return construct_value(left - right);
		  } break;
	 case BIN_MUL: {
		  int left = eval_to_value(e->binary_op.left, env);
		  int right = eval_to_value(e->binary_op.right, env);
		  return construct_value(left * right);
		  } break;
	 case BIN_DIV: {
		  int left = eval_to_value(e->binary_op.left, env);
		  int right = eval_to_value(e->binary_op.right, env);
		  return construct_value(left / right);
		  } break;
	 case BIN_MOD: {
		  int left = eval_to_value(e->binary_op.left, env);
		  int right = eval_to_value(e->binary_op.right, env);
		  return construct_value(left % right);
		  } break;
	 case BIN_SHL: {
		  int left = eval_to_value(e->binary_op.left, env);
		  int right = eval_to_value(e->binary_op.right, env);
		  return construct_value(left << right);
		  } break;
	 case BIN_SHR: {
		  int left = eval_to_value(e->binary_op.left, env);
		  int right = eval_to_value(e->binary_op.right, env);
		  return construct_value(left >> right);
		  } break;
	 case BIN_BITAND: {
		  int left = eval_to_value(e->binary_op.left, env);
		  int right = eval_to_value(e->binary_op.right, env);
		  return construct_value(left & right);
		  } break;
	 case BIN_BITOR: {
		  int left = eval_to_value(e->binary_op.left, env);
		  int right = eval_to_value(e->binary_op.right, env);
		  return construct_value(left | right);
		  } break;
	 case BIN_BITXOR: {
		  int left = eval_to_value(e->binary_op.left, env);
		  int right = eval_to_value(e->binary_op.right, env);
		  return construct_value(left ^ right);
		  } break;
	 case BIN_MEMBER: {
		  // if left is union:
		  //     return eval(x.right_ident for x in left_union)
		  // else:
		  //     return lookup(left_obj, right_ident)
		  assert(e->binary_op.right->type == EXPR_IDENT);
		  char *right_ident = e->binary_op.right->ident;
		  struct expr *left = eval_footprint_expr(e->binary_op.left, env);
		  if (left->type == EXPR_UNION) {
			   char *loop_var_name = new_ident_not_in(env, "loop_var");
			   
			   struct expr *loop_var_ident = expr_new();
			   loop_var_ident->type = EXPR_IDENT;
			   loop_var_ident->ident = loop_var_name;
			   
			   struct expr *loop_body = expr_new();
			   memcpy(loop_body, e, sizeof(struct expr));
			   //loop_body->type = EXPR_BINARY;
			   //loop_body->binary_op.op = BIN_MEMBER;
			   loop_body->binary_op.left = loop_var_ident;
			   //loop_body->binary_op.right = e->binary_op.right;

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
	 while (current != NULL) {
		  current->expr = eval_footprint_expr(current->expr, env);
		  current = current->next;
	 }
	 return e;
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
	 assert(e->for_loop.over->type == EXPR_UNION);
	 
	 struct union_node *tail = NULL;
	 struct union_node *current = e->unioned;
	 while (current != NULL) {
		  struct env_node *head_env = env_new();
		  head_env->name = e->for_loop.ident;
		  head_env->value = eval_to_object(current->expr, env);
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
	 struct union_node *tail = NULL;
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
		  int from = eval_to_value(e->subscript.from, env);
		  int to, length;
		  struct object derefed;
		  if (e->subscript.to) {
			   to = eval_to_value(e->subscript.to, env);
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
	 int i;
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
	 struct union_node *end = first;
	 while (end->next != NULL) {
		  end = end->next;
	 }
	 end->next = second;
	 return first;
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
		  unsigned long front_addr, back_addr;
		  switch (front->expr->type) {
		  case EXPR_OBJECT:
			   front_addr = front->expr->object.addr;
			   break;
		  case EXPR_EXTENT:
			   front_addr = front->expr->extent.base;
			   break;
		  default:
			   assert(false);
		  }
		  switch (back->expr->type) {
		  case EXPR_OBJECT:
			   back_addr = back->expr->object.addr;
		  case EXPR_EXTENT:
			   back_addr = back->expr->extent.base;
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

struct union_node *sorted_union_merge_extents(struct union_node *head) {
	 struct union_node *current = head;
	 struct union_node *extents = NULL;
	 struct union_node *next = NULL;
	 unsigned long base, length;
	 while (current != NULL) {
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

	 
char *print_expr_tree(struct expr *e) {
	 char *body = NULL;
	 switch (e->type) {
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
		  asprintf(&body, "%d", e->value);
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
	 int n_children = GET_CHILD_COUNT(ast);
	 char *child_str[n_children];
	 int total_strlen = n_children; // n-1 spaces and \0
	 int i;
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

int parse_int(ANTLR3_BASE_TREE *ast) {
	 assert(ast);
	 assert(GET_TYPE(ast) == INT);
	 const char * s = CCP(GET_TEXT(ast));
	 int result;
	 int n = sscanf(s, "0x%x", &result);
	 if (n == 1) {
		  return result;
	 } else {
		  n = sscanf(s, "0%o", &result);
		  if (n == 1) {
			   return result;
		  } else {
			   n = sscanf(s, "%d", &result);
			   if (n == 1) {
					return result;
			   } else {
					assert(false);
			   }
		  }
	 }
	 return 0;
}

struct expr *parse_antlr_tree(ANTLR3_BASE_TREE *ast) {
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
	 default:
		  assert(false);
	 }

	 switch (e->type) {
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
		  assert(GET_CHILD_COUNT(ast) == 3);
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
		  ANTLR3_BASE_TREE *subscr = GET_CHILD(ast, 2);
		  switch (GET_TYPE(subscr)) {
		  case SUBSCRIPT_SCALAR:
			   assert(GET_CHILD_COUNT(subscr) == 1);
			   e->subscript.from = parse_antlr_tree(GET_CHILD(subscr, 0));
			   break;
		  case SUBSCRIPT_RANGE:
			   assert(GET_CHILD_COUNT(subscr) == 2);
			   e->subscript.from = parse_antlr_tree(GET_CHILD(subscr, 0));
			   e->subscript.to = parse_antlr_tree(GET_CHILD(subscr, 1));
			   break;
		  default:
			   assert(false);
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

void print_tree_types(ANTLR3_BASE_TREE *ast) {
	 printf("(%d[%s] ", GET_TYPE(ast), CCP(GET_TEXT(ast)));
	 _Bool first = true;
	 FOR_ALL_CHILDREN(ast) {
		  if (first) {
			   first = false;
		  } else {
			   printf(" ");
		  }
		  print_tree_types(n);
	 }
	 printf(")");
}

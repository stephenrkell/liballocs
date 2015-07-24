#define _GNU_SOURCE

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include <dwarfidl/parser_includes.h>
#include "liballocs.h"
#include "footprints.h"

#include "footprints_antlr_macros.h"

struct function parse_function(void *ptr) {
	ANTLR3_BASE_TREE *func_ast = (ANTLR3_BASE_TREE*)ptr;
	assert(func_ast);
	assert(GET_TYPE(func_ast) == FP_FUN);
	assert(GET_CHILD_COUNT(func_ast) == 3);

	ANTLR3_BASE_TREE *name_ast = GET_CHILD(func_ast, 0);
	ANTLR3_BASE_TREE *args_ast = GET_CHILD(func_ast, 1);
	ANTLR3_BASE_TREE *expr_ast = GET_CHILD(func_ast, 2);

	struct function func;

	// name
	assert(GET_TYPE(name_ast) == IDENTS);
	func.name = parse_ident(name_ast);

	// expr
	func.expr = parse_antlr_tree(expr_ast);

	// args
	func.args = NULL;
	// in reverse order for easy linked-list-consing which would otherwise reverse it again
	for (int i = GET_CHILD_COUNT(args_ast) - 1; i >= 0; i--) {
		ANTLR3_BASE_TREE *arg = GET_CHILD(args_ast, i);
		assert(GET_TYPE(arg) == IDENTS);
		func.args = string_node_new_with(parse_ident(arg), func.args);
	}


	return func; //env_new_with(func.name, construct_function(func), next);
}

struct footprint_node *parse_footprints_from_file(const char *filename, struct env_node **output_env) {
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

	struct env_node *defined_functions = NULL;

	assert(GET_TYPE(ast) == DIES);

	fprintf(stderr, "%s\n", TO_STRING_TREE(ast)->chars);

	for (size_t i = 0; i < GET_CHILD_COUNT(ast); i++) {
		ANTLR3_BASE_TREE *die = GET_CHILD(ast, i);
		if (GET_TYPE(die) == DIE &&
		    GET_CHILD_COUNT(die) > 0 &&
		    GET_TYPE(GET_CHILD(die, 0)) == KEYWORD_TAG &&
		    strcmp(CCP(GET_TEXT(GET_CHILD(die, 0))), "subprogram") == 0) {
			prints = new_from_subprogram_DIE(die, prints);
		} else if (GET_TYPE(die) == FP_FUN &&
		           GET_CHILD_COUNT(die) > 0) {
			struct function func = parse_function(die);
			defined_functions = env_new_with(func.name, construct_function(func), defined_functions);
		}
	}

	*output_env = defined_functions;
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

char *parse_ident(void *ptr) {
	ANTLR3_BASE_TREE *ast = (ANTLR3_BASE_TREE*)ptr;
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

int64_t parse_int(void *ptr) {
	ANTLR3_BASE_TREE *ast = (ANTLR3_BASE_TREE*)ptr;
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
	case FP_APP:
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
	case FP_FUN:
		e->type = EXPR_FUNCTION;
		break;
	case FP_ARGS:
		e->type = EXPR_FUNCTION_ARGS;
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
		case FP_APP:
			e->binary_op.op = BIN_APP;
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
	case EXPR_FUNCTION: {
		e->func = parse_function(ast);
	} break;
	case EXPR_FUNCTION_ARGS: { // function args are just a union, but must be the right way around
		struct union_node *tail = NULL;
		for (int i = GET_CHILD_COUNT(ast) - 1; i >= 0; i--) {
			tail = union_new_with(parse_antlr_tree(GET_CHILD(ast, i)), tail);
		}
		e->unioned = tail;
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

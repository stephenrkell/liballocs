#ifndef __FOOTPRINTS_ENUMS_H__
#define __FOOTPRINTS_ENUMS_H__

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

enum footprint_direction {
	FOOTPRINT_READ,
	FOOTPRINT_WRITE,
	FOOTPRINT_READWRITE
};

extern const char *binary_ops_str[];
extern const char *unary_ops_str[];
extern const char *subscript_methods_str[];
extern const char *expr_types_str[];
extern const char *footprint_direction_str[];

#endif

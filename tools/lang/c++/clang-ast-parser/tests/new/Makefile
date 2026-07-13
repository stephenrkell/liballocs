CLANG_AST_PARSER = ../../../bin/clang-ast-parser

SRCS = $(wildcard *.cpp)
$(info $$SRCS = $(SRC))

parse:
	$(CLANG_AST_PARSER) $(SRCS)

gdb-parse:
	gdb $(CLANG_AST_PARSER)

ast-dump:
	clang -Xclang -ast-dump -fsyntax-only $(SRCS)


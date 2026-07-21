CLANG_AST_PARSER = ../../../bin/clang-ast-parser

TEST_NAME = templates
SRC = $(TEST_NAME).cpp
ACTUAL = $(TEST_NAME).i.allocs
EXPECTED = $(TEST_NAME).i.allocs.expected

NORMALIZE = sed -i 's|^.*/tests/|tests/|'

.PHONY: test update-expected gdb-parse ast-dump

$(ACTUAL): $(SRC)
	$(CLANG_AST_PARSER) $(SRC)

test:
	$(CLANG_AST_PARSER) $(SRC)
	$(NORMALIZE) $(ACTUAL) > /dev/null
	@diff -yq $(ACTUAL) $(EXPECTED) \
		&& echo "PASS: $(TEST_NAME)" \
		|| (echo "FAIL: $(TEST_NAME)"; exit 1)

update-expected:
	mv $(ACTUAL) $(EXPECTED)

gdb-parse:
	gdb $(CLANG_AST_PARSER)

ast-dump:
	clang -Xclang -ast-dump -fsyntax-only $(SRC)

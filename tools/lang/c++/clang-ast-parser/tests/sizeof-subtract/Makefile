CLANG_AST_PARSER = ../../../bin/clang-ast-parser

TEST_NAME = sizeof-subtract
SRC = $(TEST_NAME).cpp
ACTUAL = $(TEST_NAME).i.allocs
EXPECTED = $(TEST_NAME).i.allocs.expected

NORMALIZE = sed -i 's|^.*/tests/|tests/|; s|dumpallocs_synthetic_[a-zA-Z0-9_$$]*\$$2ftests\$$2f|dumpallocs_synthetic_\$$2ftests\$$2f|g'

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

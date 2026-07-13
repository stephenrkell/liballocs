CLANG_AST_PARSER = ../../../bin/clang-ast-parser

TEST_NAME = custom-alloc
SRC = $(TEST_NAME).cpp
ACTUAL = $(TEST_NAME).i.allocs
EXPECTED = $(TEST_NAME).i.allocs.expected

NORMALIZE = sed -i 's|^.*/tests/|tests/|'

# All three user-defined functions registered via the env vars the C tool uses.
ALLOC_ENV = LIBALLOCS_ALLOC_FNS="my_malloc(Z)p my_calloc(zZ)p" \
            LIBALLOCS_SUBALLOC_FNS="pool_alloc(pZ)p"

.PHONY: test update-expected

$(ACTUAL): $(SRC)
	$(ALLOC_ENV) $(CLANG_AST_PARSER) $(SRC)

test: $(ACTUAL)
	$(NORMALIZE) $(ACTUAL) > /dev/null
	@diff -yq $(ACTUAL) $(EXPECTED) \
		&& echo "PASS: $(TEST_NAME)" \
		|| (echo "FAIL: $(TEST_NAME)"; exit 1)

update-expected:
	mv $(ACTUAL) $(EXPECTED)

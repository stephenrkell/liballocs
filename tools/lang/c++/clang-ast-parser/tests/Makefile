TESTS = malloc new offsetof sizeof sizeof-subtract templates custom-alloc

.PHONY: test clean $(TESTS)

test: $(TESTS)

$(TESTS):
	$(MAKE) -C $@ test

clean:
	for t in $(TESTS); do $(MAKE) -C $$t clean || true; done

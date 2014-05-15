default: src lib tools tests

.PHONY: src
src: | tools
	$(MAKE) -C src

.PHONY: tools
tools:
	$(MAKE) -C tools

.PHONY: lib
lib: src
	mkdir -p lib && cd lib && \
    ln -sf ../src/liballocs.so ../src/liballocs_noop.so ../src/liballocs_preload.so . && \
    ln -sf ../src/noop.o liballocs_noop.o && \
    ln -sf ../src/liballocs.a ../src/liballocs_preload.a .

.PHONY: clean
clean:
	$(MAKE) -C src clean
	$(MAKE) -C tools clean
	rm -f lib/*.so lib/*.o lib/.??*
	$(MAKE) -C tests clean

.PHONY: tests
tests:
	$(MAKE) -C tests

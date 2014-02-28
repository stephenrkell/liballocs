default: src lib frontend test

.PHONY: src
src: | allocsites
	$(MAKE) -C src

.PHONY: allocsites
allocsites:
	$(MAKE) -C allocsites

.PHONY: frontend
frontend: | allocsites
	$(MAKE) -C frontend

.PHONY: lib
lib: src
	mkdir -p lib && cd lib && \
    ln -sf ../src/libcrunch.so ../src/libcrunch_noop.so ../src/libcrunch_preload.so . && \
    ln -sf ../src/noop.o libcrunch_noop.o

.PHONY: clean
clean:
	$(MAKE) -C src clean
	$(MAKE) -C allocsites clean
	rm -f lib/*.so lib/*.o lib/.??*
	$(MAKE) -C frontend clean
	$(MAKE) -C test clean

default: src lib frontend test

.PHONY: src
src:
	$(MAKE) -C src

.PHONY: frontend
frontend:
	$(MAKE) -C frontend

.PHONY: lib
lib: src
	mkdir -p lib && cd lib && ln -sf ../src/libcrunch.so ../src/stubs.o ../src/libcrunch_noop.so ../src/libcrunch_noop.o ../src/libcrunch_preload.so .

.PHONY: clean
clean:
	$(MAKE) -C src clean
	rm -f lib/libcrunch.so lib/stubs.o lib/.??*
	$(MAKE) -C frontend clean
	$(MAKE) -C test clean

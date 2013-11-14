.PHONY: src
src:
	$(MAKE) -C src

.PHONY: frontend
frontend:
	$(MAKE) -C frontend

.PHONY: lib
lib: src
	mkdir -p lib && cd lib && ln -sf ../src/libcrunch.so ../src/stubs.o .

.PHONY: clean
clean:
	$(MAKE) -C src clean
	rm -f lib/* lib/.??*
	$(MAKE) -C frontend clean
	$(MAKE) -C test clean

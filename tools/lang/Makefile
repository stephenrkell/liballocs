default: all
all: c c++
install: ; # nothing

.PHONY: c
c:
	$(MAKE) -C c

.PHONY: c++
c++:
	$(MAKE) -C c++

.PHONY: test
test:
	$(MAKE) -C c++ test

.PHONY: clean
clean:
	$(MAKE) -C c clean
	$(MAKE) -C c++ clean

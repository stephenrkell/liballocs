.PHONY: default
default:
	for d in $(shell find -mindepth 1 -maxdepth 1 -type d); do $(MAKE) -C $$d -f ../rules.mk `if [ -e $$d/Makefile ]; then printf "%s" "-f Makefile"; fi` Dockerfile ; done

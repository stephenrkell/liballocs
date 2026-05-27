# the dockerfile template lives in the same dir as these makerules
vpath Dockerfile.template $(dir $(lastword $(MAKEFILE_LIST)))

Dockerfile: Dockerfile.template Dockerfile.env
	cat $< | (. ./$(filter Dockerfile.env,$+) && \
            envsubst '$$DISTRIBUTION $$PACKAGES $$MAKE_PARALLELISM' ) > $@ || (rm -f "$@"; false)

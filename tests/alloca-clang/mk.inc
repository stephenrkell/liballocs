LIBALLOCS ?= $(realpath $(dir $(lastword $(MAKEFILE_LIST)))/../..)
export LIBALLOCS        # the linker plugin needs this
export META_CC := cc    # ... and this? FIXME: no, gold-plugin.cpp is fine, so where is this needed?

# HACK: srk's system has ancient clang-13 installed currently
CLANG ?= $(shell which clang || echo clang-13)

# To use clang, we need to use allocs-wrap, which is slow because it
# uses the new compiler wrapper scripts (recent revisions of toolsub/wrapper)
# which are a big pile of awk/bash and need to be rewritten in C
CC := $(LIBALLOCS)/tools/allocs-wrap $(shell which $(CLANG))

# FIXME: why does allocs-wrap not sort this by itself? The allocs-*flags
# scripts are supposed to be an alternative to allocs-wrap.
# It doesn't sort it, perhaps because it does not want to give ldflags to
# every cc invocation. It could though, harmlessly, presumably? What happened
# to our wrapper's notion of "single-function commands"? How should the
# one-shot "allocs-wrap" share logic with allocs-ldflags or even allocs-cflags?
LDFLAGS += `$(LIBALLOCS)/tools/allocs-ldflags`

# debugging
CPPFLAGS += -Wp,-dD -Wp,-save-temps

CPPFLAGS += -fno-addrsig # HACK but by itself doesn't work... hacked toolsub 'wrapper' to undo -faddrsig that creeps in earlier

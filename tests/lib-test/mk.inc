# lib-test is a plain old C program, not allocscc'd, and it
# dlopens liballocs (test build) to run its self-test constructors.
export CC := cc
export CFLAGS := -fPIC -O0 -g3 -DTEST
export LDLIBS := -ldl
export LIBALLOCS_BUILD := $(realpath $(dir $(realpath $(THIS_MAKEFILE)))../..)/build/test/liballocs_preload.so
export LD_PRELOAD := # empty
export PRELOAD := # empty
export LIBALLOCS_USE_PRELOAD := no

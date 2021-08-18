export LIBALLOCS_BUILD := $(realpath $(dir $(realpath $(THIS_MAKEFILE)))../..)/build/test/liballocs_preload.so
export LD_PRELOAD := # empty
export PRELOAD := # empty
export LIBALLOCS_USE_PRELOAD := no

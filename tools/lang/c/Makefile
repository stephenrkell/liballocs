# This makefile handles all the CIL building for our subdirs
# (currently dumpallocs and trumptr)
CIL_TOOLS := dumpallocs trumptr
CIL ?= $(realpath $(dir $(lastword $(MAKEFILE_LIST))))/../../../cil

CIL_TOOLS_SRC := $(shell find $(CIL_TOOLS) -name '*.ml')
THIS_MAKEFILE := $(lastword $(MAKEFILE_LIST))
CIL_EXTRASRC := $(addprefix $(realpath $(dir $(THIS_MAKEFILE)))/,$(CIL_TOOLS))

default: lib $(CIL)/bin/cilly sanity-tests

%.cil.o: %.c $(CIL)/bin/cilly
	cd "$(dir $<)" && $(CIL)/bin/cilly --do$$( echo $(dir $<) | tr -d '/' ) --save-temps -c -o "$(notdir $@)" "$(notdir $<)"

clean:
	for dir in $(CIL_TOOLS); do (cd $$dir && rm -f *.o *.cil.c *.i ); done

$(CIL)/bin/cilly: $(CIL_TOOLS_SRC)
	cd $(CIL) && \
	(grep '$(firstword $(CIL_TOOLS))' config.log || \
	    ./configure EXTRASRCDIRS="$(CIL_EXTRASRC)" EXTRAFEATURES="$(CIL_TOOLS)" ) && \
	COMPILE_FLAGS=-g $(MAKE) && \
	touch $(CIL)/bin/cilly

.PHONY: sanity-tests
sanity-tests: | default
	$(MAKE) -C ../../test cleanrun-hello cleanrun-hello-errno cleanrun-hello-static cleanrun-hello-stack cleanrun-hello-heap

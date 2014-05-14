CIL_TOOLS := dumpallocs #trumptr
CIL ?= $(realpath $(dir $(lastword $(MAKEFILE_LIST))))/../../../../cil

CIL_TOOLS_SRC := $(shell find $(CIL_TOOLS) -name '*.ml')
THIS_MAKEFILE := $(lastword $(MAKEFILE_LIST))
CIL_EXTRASRC := $(addprefix $(realpath $(dir $(THIS_MAKEFILE)))/,$(CIL_TOOLS))

default: src $(CIL)/bin/cilly 

%.cil.o: %.c $(CIL)/bin/cilly
	cd "$(dir $<)" && $(CIL)/bin/cilly --do$$( echo $(dir $<) | tr -d '/' ) --save-temps -c -o "$(notdir $@)" "$(notdir $<)"

clean:
	for dir in $(CIL_TOOLS); do (cd $$dir && rm -f *.o *.cil.c *.i ); done
	$(MAKE) -C src clean

$(CIL)/bin/cilly: $(CIL_TOOLS_SRC)
	cd $(CIL) && \
	(grep '$(firstword $(CIL_TOOLS))' config.log || \
	    ./configure EXTRASRCDIRS="$(CIL_EXTRASRC)" EXTRAFEATURES="$(CIL_TOOLS)" ) && \
	COMPILE_FLAGS=-g $(MAKE) && \
	touch $(CIL)/bin/cilly

.PHONY: src
src:
	$(MAKE) -C src

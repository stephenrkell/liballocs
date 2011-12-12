# This makefile handles all the CIL building for our subdirs
# (currently dumpallocs and trumptr)
CIL_TOOLS := dumpallocs trumptr
CIL ?= $(realpath $(dir $(lastword $(MAKEFILE_LIST))))/../cil

CIL_TOOLS_SRC := $(shell find $(CIL_TOOLS) -name '*.ml')
$(warning CIL_TOOLS_SRC is $(CIL_TOOLS_SRC))

default: $(CIL)/bin/cilly $(patsubst %.c,%.cil.o,$(filter-out %.cil.c,$(wildcard */*.c)))

%.cil.o: %.c $(CIL)/bin/cilly
	cd "$(dir $<)" && $(CIL)/bin/cilly --do$$( echo $(dir $<) | tr -d '/' ) --save-temps -c -o "$(notdir $@)" "$(notdir $<)"

clean:
	for dir in $(CIL_TOOLS); do (cd $$dir && rm -f *.o *.cil.c *.i ); done

$(CIL)/bin/cilly: $(CIL_TOOLS_SRC)
	cd $(CIL) && grep '$(firstword $(CIL_TOOLS))' config.log || ./configure \
	EXTRASRC="$(addprefix $(realpath $(dir $(lastword $(MAKEFILE_LIST))))/,$(CIL_TOOLS))" \
	EXTRAFEATURES="$(CIL_TOOLS)"
	$(MAKE) -C $(CIL) && touch $(CIL)/bin/cilly

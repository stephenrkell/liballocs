THIS_MAKEFILE := $(lastword $(MAKEFILE_LIST))

OCAMLFIND ?= ocamlfind
CILLY ?= cilly
CIL_TOOLS := dumpallocs monalloca #trumptr
OCAMLFLAGS +=  -package findlib -package cil
OCAMLFLAGS += -I $(dir $(THIS_MAKEFILE))/lib

CIL_TOOLS_SRC := $(shell find $(CIL_TOOLS) $(realpath $(dir $(THIS_MAKEFILE)))/lib -name '*.ml') 

default: src bin cil

OCAML_DEPS := $(patsubst %.ml,%.d,$(CIL_TOOLS_SRC))

$(OCAML_DEPS): %.d: %.ml
	$(OCAMLFIND) ocamldep $(filter-out -g,$(OCAMLOPTFLAGS)) $(OCAMLFLAGS) "$<" > "$@"

DEPS += $(OCAML_DEPS)
-include $(DEPS)

.PHONY: cil
cil: $(foreach t,$(CIL_TOOLS),$(t)/$(t).cmxs $(t)/$(t).cma)

# for reproducing that bug!
dumpallocs/dumpallocs.borked.cmxs: lib/cilallocs.cmx dumpallocs/dumpallocs.cmx 
	$(OCAMLFIND) ocamlopt -shared -o "$@" $(OCAMLOPTFLAGS) -linkpkg $(OCAMLFLAGS) $+
null/null.borked.cmxs: null/null.cmx 
	$(OCAMLFIND) ocamlopt -shared -o "$@" $(OCAMLOPTFLAGS) -linkpkg $(OCAMLFLAGS) $+

%.cmxs: lib/cilallocs.cmx %.cmx 
	$(OCAMLFIND) ocamlopt -shared -o "$@" $(OCAMLOPTFLAGS) $(OCAMLFLAGS) $+
%.cmx %.cmi: %.ml
	$(OCAMLFIND) ocamlopt -o "$@" $(OCAMLOPTFLAGS) $(OCAMLFLAGS) -c "$<"
%.cmo %.cmi: %.ml
	$(OCAMLFIND) ocamlc -o "$@" $(OCAMLFLAGS) -c "$<"
%.cma: lib/cilallocs.cmo %.cmo
	$(OCAMLFIND) ocamlc -o "$@" $(OCAMLFLAGS) -a $+

# for testing
%.cil.o: %.c
	cd "$(dir $<)" && $(CILLY) --do$$( echo $(dir $<) | tr -d '/' ) --save-temps -c -o "$(notdir $@)" "$(notdir $<)"

clean:
	for dir in $(CIL_TOOLS); do (cd $$dir && rm -f *.o *.cmo *.cma *.cmi *.cmx *.cmxa *.cmxs *.cil.c *.i ); done
	rm -f lib/*.o lib/*.cmo lib/*.cma lib/*.cmi lib/*.cmx lib/*cmxa lib/*cmxs
	$(MAKE) -C src clean

.PHONY: src
src:
	$(MAKE) -C src

.PHONY: bin
bin: src
	cd bin && ln -sf ../src/base-types-translation .

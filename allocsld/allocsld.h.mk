export DT_ALLOCS_BOOTSTRAP_RELA := 0x6ffffa01
export DT_ALLOCS_BOOTSTRAP_RELASZ := 0x6ffffa02
export DT_ALLOCS_BOOTSTRAP_RELAENT := 0x6ffffa03
allocsld.h:
	( printf '#ifndef LIBALLOCS_ALLOCSLD_H_\n#define LIBALLOCS_ALLOCSLD_H_\n'; \
	 for v in DT_ALLOCS_BOOTSTRAP_RELA DT_ALLOCS_BOOTSTRAP_RELASZ DT_ALLOCS_BOOTSTRAP_RELAENT; do \
	   printf "#define $$v "; eval printf $$"$${v}\\\n"; done; printf '#endif\n' ) > "$@" || (rm -f "$@"; false)

/* We are a fragment of C code, called from a late pre-entry context in donald.
 * We care about "program" phdrs because it's "the program" that needs a DT_DEBUG
 * entry. It might be  they're the ones where we need to
 *  */
cover_tracks(we_are_the_program, program_phdrs,
	program_phnum, SYSTEM_LDSO_PATH,
	inferior.dynamic_vaddr, inferior.base_addr);

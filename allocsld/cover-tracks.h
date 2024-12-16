struct link_map;
extern struct link_map fake_ld_so_link_map;

void cover_tracks(_Bool we_are_the_program, ElfW(Phdr) *program_phdrs, unsigned program_phnum, const char *ldso_path, uintptr_t inferior_dynamic_vaddr, uintptr_t base_addr);

void instrument_ld_so_allocators(uintptr_t ld_so_load_addr);

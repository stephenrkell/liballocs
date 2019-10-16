/* Gold plugin for liballocs.
 * 
 * Copyright 2017, Stephen Kell <stephen.kell@cl.cam.ac.uk>
 * 
 * This duplicates the logic of allocscompilerwrapper.py,
 * but should ultimately be faster.
 * 
 * Since we only run at link time, not after compilation, we
 * assume that input .o files have not yet undergone any of the
 * usual post-compile/assembly fixups (link-used-types etc.).
 */

#include <vector>
#include <string>
#include <regex>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <libgen.h> /* for dirname() and GNU basename() -- must include before cstring */
#include <cstring>
#include <sys/mman.h>
#include <elf.h>
#include <cassert>
#include "plugin-api.h"
#include <unistd.h> /* for sleep() */
#include <boost/algorithm/string.hpp> /* for split, is_any_of */
#include <sys/types.h> /* for fstat() */
#include <sys/stat.h> /* for fstat() */
#include <unistd.h> /* for fstat(), write(), read() */
#include <utility> /* for pair */
//#include <experimental/optional>
#include <boost/optional.hpp>
extern "C" {
#include <link.h>
}
#include "uniqtypes.hpp"
#include "relf.h" /* to get our own binary's realpath -- bit of a HACK */

using std::vector;
using std::string;
using std::smatch;
using std::regex;
using std::regex_match;
using std::pair;
using std::make_pair;
// using std::experimental::optional;
using boost::optional;

using namespace allocs::tool;

/* Firstly let's reimplement all the helper logic of allocscompilerwrapper.py. */
vector<string> 
default_l1_alloc_fns()
{
	return vector<string>();
}
vector<string> 
default_l1_free_fns()
{
	return vector<string>();
}
vector<string>
word_split_env(const string &k)
{
	// return [s for s in os.environ.get(key, "").split(' ') if s != '']
	vector<string> strs;
	const char *s = getenv(k.c_str());
	if (!s) s = "";
	boost::split(strs, s, boost::is_any_of("\t "));
	return strs;
}
vector<string>
all_l1_or_wrapper_alloc_fns()
{
	vector<string> out = default_l1_alloc_fns();
	for (string s : word_split_env("LIBALLOCS_ALLOC_FNS"))
	{
		out.push_back(s);
	}
	return out;
}
vector<string>
all_sub_alloc_fns()
{
	return word_split_env("LIBALLOCS_SUB_ALLOC_FNS");
}
vector<string>
all_alloc_sz_fns()
{
	return word_split_env("LIBALLOCS_ALLOCSZ_FNS");
}
vector<string>
all_alloc_fns()
{
	vector<string> out = all_l1_or_wrapper_alloc_fns();
	for (string s : all_sub_alloc_fns()) out.push_back(s);
	for (string s : all_alloc_sz_fns()) out.push_back(s);
	return out;
}
vector<string>
all_l1_free_fns()
{
	vector<string> out = default_l1_free_fns();
	for (string s : word_split_env("LIBALLOCS_FREE_FNS")) out.push_back(s);
	return out;
}
vector<string>
all_sub_free_fns()
{
	return word_split_env("LIBALLOCS_SUBFREE_FNS");
}
vector<string>
all_free_fns()
{
	vector<string> out = all_l1_free_fns();
	for (string s : all_sub_free_fns()) out.push_back(s);
	return out;
}
static vector<string> free_fns;
vector<string>
all_wrapped_sym_names()
{
	vector<string> out;
	for (string alloc_fn : all_alloc_fns())
	{
		if (alloc_fn == "") continue;
		smatch m;
		if (regex_match(alloc_fn, m, regex("(.*)\\((.*)\\)(.?)")))
		{
			out.push_back(m[1]);
		}
	}
	for (string free_fn : all_sub_free_fns())
	{
		if (free_fn == "") continue;
		smatch m;
		if (regex_match(free_fn, m, regex("(.*)\\((.*)\\)(.?)")))
		{
			out.push_back(m[1]);
		}
	}
	for (string free_fn : all_l1_free_fns())
	{
		if (free_fn == "") continue;
		smatch m;
		if (regex_match(free_fn, m, regex("(.*)\\((.*)\\)")))
		{
			out.push_back(m[1]);
		}
	}
	return out;
}
static vector<string> wrapped_sym_names;
string::const_iterator
find_first_upper_case(const string& s)
{
	for (auto i_c = s.begin(); i_c != s.end(); ++i_c)
	{
		if (isupper(*i_c)) return i_c;
	}
	return s.end();
}
/* Horrible HACK: assume that our plugin ld.so resides within a liballocs
 * tree, and use the link map to fish out its path. WHY do we need to
 * know the liballocs base dir? It's to add -L and -rpath options.
 * If we can eliminate the liballocs dummyweaks DT_NEEDED, we won't
 * need any of this and it'll be cleaner. (Won't work for libcrunch's
 * stubs library, but let's worry about that over in libcrunch/.) */
static
string
get_liballocs_base_dir()
{
	string plugin_path
	 = get_highest_loaded_object_below(reinterpret_cast<void*>(&get_liballocs_base_dir))->l_name;
	return string(dirname(const_cast<char*>(plugin_path.c_str()))) + "/../";
}
string
get_lib_name_stem()
{
	return "allocs";
}
string
get_dummy_weak_object_name_stem()
{
	return "dummyweaks";
}
vector<string>
get_dummy_weak_link_args()
{
	/* FIXME: this needs to be done differently in gold-plugin-land. 
	

    def getDummyWeakLinkArgs(self, outputIsDynamic, outputIsExecutable):
        if outputIsDynamic and outputIsExecutable:
            return [ "-Wl,--push-state", "-Wl,--no-as-needed", \
                    self.getLinkPath() + "/lib" + self.getLibNameStem() + "_" + self.getDummyWeakObjectNameStem() + ".so", \
                    "-Wl,--pop-state" ]
        elif outputIsDynamic and not outputIsExecutable:
            return [self.getLinkPath() + "/lib" + self.getLibNameStem() + "_" + self.getDummyWeakObjectNameStem() + ".o"]
        else:
            return []
	
	
	*/
	
}
string get_ld_lib_base()
{
	return string("-l") + get_lib_name_stem();
}
string get_link_path()
{
	return get_liballocs_base_dir() + "lib";
}
string get_run_path()
{
	return get_link_path();
}
vector<string>
get_basic_compiler_command()
{
	/* This is the "underlying" compiler. */
	/* please override me */
	return vector<string>({ "cc" });
}
vector<string>
get_basic_c_compiler_command()
{
	/* Unlike in the compiler wrapper case, this is not hard;
	 * all we need is the system cc. */
	return vector<string>({ "cc" });
}
vector<string>
get_compiler_command(const vector<string>& items_and_options)
{
	// FIXME: ensure that fsanitize=crunch has added -ffunction-sections
	// and turned on strict DWARF
	// and frame pointers
	vector<string> out = get_basic_compiler_command();
	for (string s : items_and_options) out.push_back(s);
	return out;
}
vector<pair<string, const Elf64_Sym *> >
symbols_with(const Elf64_Sym *symtab, 
	const Elf64_Sym *symtab_end,
	const char *strtab,
	const std::function<bool(const Elf64_Sym *, const string&)>& f
)
{
	vector<pair<string, const Elf64_Sym *> > out;
	for (; symtab != symtab_end; ++symtab)
	{
		string name = strtab + symtab->st_name;
		if (f(symtab, name)) out.push_back(make_pair(name, symtab));
	}
	return out;
}

vector<pair<string, const Elf64_Sym *> >
symbols_matching(const Elf64_Sym *symtab,
	const Elf64_Sym *symtab_end,
	const char *strtab,
	const vector<string>& patterns /* must be alternation-free */,
	const std::function<bool(const Elf64_Sym *, const string&)>& extra_pred) // must be alternation-free
{
	string big_pattern;
	std::ostringstream s;
	for (auto i = patterns.begin(); i != patterns.end(); ++i)
	{
		if (i != patterns.begin()) s << "|";
		s << *i;
	}
	big_pattern = s.str();
	// fprintf(stderr, "Looking for symbols matching big pattern: %s\n", big_pattern.c_str());
	auto pred = [big_pattern, extra_pred](const Elf64_Sym *s, const string& name) {
		if (extra_pred(s, name))
		{
			smatch m;
			if (regex_match(name, m, regex(big_pattern)))
			{
				fprintf(stderr, "Saw symbol matching pred and pattern (%s): %s\n", 
					big_pattern.c_str(), name.c_str());
				return true;
			}
		}
		return false;
	};
	return symbols_with(symtab, symtab_end, strtab, pred);
}

vector<pair<string, const Elf64_Sym *> >
defined_symbols_matching(const Elf64_Sym *symtab, 
	const Elf64_Sym *symtab_end,
	const char *strtab,
	const vector<string>& patterns) // must be alternation-free
{
	return symbols_matching(symtab, symtab_end, strtab, patterns, 
		[](const Elf64_Sym *s, const string& f) {
			return s->st_shndx != SHN_UNDEF;
		});
}

vector<pair<string, const Elf64_Sym *> >
undefined_symbols_matching(const Elf64_Sym *symtab, 
	const Elf64_Sym *symtab_end,
	const char *strtab,
	const vector<string>& patterns) // must be alternation-free
{
	return symbols_matching(symtab, symtab_end, strtab, patterns, 
		[](const Elf64_Sym *s, const string& f) {
			return s->st_shndx == SHN_UNDEF;
		});
}
/* What things can we do to an input file? */
struct unbind
{
	string sym;
};
struct stubgen
{
	
};

static vector<string> temp_files_to_unlink;

pair<string, int> new_temp_file(const string& insert)
{
	char *tempnambuf = strdup(("/tmp/tmp." + insert + ".XXXXXX").c_str());
	int tmpfd = mkstemp(tempnambuf);
	if (tmpfd == -1) abort(); // FIXME: better diagnostics
	string tempnam = tempnambuf;
	free(tempnambuf);
	temp_files_to_unlink.push_back(tempnam);
	return make_pair(tempnam, tmpfd);
}

/* These will be initialized from the transfer vector. */
static int output_file_type = -1;
static int api_version;
static int gold_version;
static int gnu_ld_version;

/* Linker interfaces: direct interaction. */

/* The linker's interface for adding symbols from a claimed input file.  */
enum ld_plugin_status
(*add_symbols) (void *handle, int nsyms,
                          const struct ld_plugin_symbol *syms);

/* The linker's interface for getting the input file information with
   an open (possibly re-opened) file descriptor.  */
enum ld_plugin_status
(*get_input_file) (const void *handle,
                             struct ld_plugin_input_file *file);

enum ld_plugin_status
(*get_view) (const void *handle, const void **viewp);

/* The linker's interface for releasing the input file.  */
enum ld_plugin_status
(*release_input_file) (const void *handle);

/* The linker's interface for retrieving symbol resolution information.  */
enum ld_plugin_status
(*get_symbols) (const void *handle, int nsyms,
                          struct ld_plugin_symbol *syms);

/* The linker's interface for adding a compiled input file.  */
enum ld_plugin_status
(*add_input_file) (const char *pathname);

/* The linker's interface for adding a library that should be searched.  */
enum ld_plugin_status
(*add_input_library) (const char *libname);

/* The linker's interface for adding a library path that should be searched.  */
enum ld_plugin_status
(*set_extra_library_path) (const char *path);

/* The linker's interface for issuing a warning or error message.  */
enum ld_plugin_status
(*message) (int level, const char *format, ...);

/* The linker's interface for retrieving the number of sections in an object.
   The handle is obtained in the claim_file handler.  This interface should
   only be invoked in the claim_file handler.   This function sets *COUNT to
   the number of sections in the object.  */
enum ld_plugin_status
(*get_input_section_count) (const void* handle, unsigned int *count);

/* The linker's interface for retrieving the section type of a specific
   section in an object.  This interface should only be invoked in the
   claim_file handler.  This function sets *TYPE to an ELF SHT_xxx value.  */
enum ld_plugin_status
(*get_input_section_type) (const struct ld_plugin_section section,
                                     unsigned int *type);

/* The linker's interface for retrieving the name of a specific section in
   an object. This interface should only be invoked in the claim_file handler.
   This function sets *SECTION_NAME_PTR to a null-terminated buffer allocated
   by malloc.  The plugin must free *SECTION_NAME_PTR.  */
enum ld_plugin_status
(*get_input_section_name) (const struct ld_plugin_section section,
                                     char **section_name_ptr);

/* The linker's interface for retrieving the contents of a specific section
   in an object.  This interface should only be invoked in the claim_file
   handler.  This function sets *SECTION_CONTENTS to point to a buffer that is
   valid until clam_file handler returns.  It sets *LEN to the size of the
   buffer.  */
enum ld_plugin_status
(*get_input_section_contents) (const struct ld_plugin_section section,
                                         const unsigned char **section_contents,
                                         size_t* len);

/* The linker's interface for specifying the desired order of sections.
   The sections should be specifed using the array SECTION_LIST in the
   order in which they should appear in the final layout.  NUM_SECTIONS
   specifies the number of entries in each array.  This should be invoked
   in the all_symbols_read handler.  */
enum ld_plugin_status
(*update_section_order) (const struct ld_plugin_section *section_list,
				   unsigned int num_sections);

/* The linker's interface for specifying that reordering of sections is
   desired so that the linker can prepare for it.  This should be invoked
   before update_section_order, preferably in the claim_file handler.  */
enum ld_plugin_status
(*allow_section_ordering) (void);

/* The linker's interface for specifying that a subset of sections is
   to be mapped to a unique segment.  If the plugin wants to call
   unique_segment_for_sections, it must call this function from a
   claim_file_handler or when it is first loaded.  */
enum ld_plugin_status
(*allow_unique_segment_for_sections) (void);

/* The linker's interface for specifying that a specific set of sections
   must be mapped to a unique segment.  ELF segments do not have names
   and the NAME is used as the name of the newly created output section
   that is then placed in the unique PT_LOAD segment.  FLAGS is used to
   specify if any additional segment flags need to be set.  For instance,
   a specific segment flag can be set to identify this segment.  Unsetting
   segment flags that would be set by default is not possible.  The
   parameter SEGMENT_ALIGNMENT when non-zero will override the default.  */
enum ld_plugin_status
(*unique_segment_for_sections) (
    const char* segment_name,
    uint64_t segment_flags,
    uint64_t segment_alignment,
    const struct ld_plugin_section * section_list,
    unsigned int num_sections);

/* The linker's interface for retrieving the section alignment requirement
   of a specific section in an object.  This interface should only be invoked in the
   claim_file handler.  This function sets *ADDRALIGN to the ELF sh_addralign
   value of the input section.  */
enum ld_plugin_status
(*get_input_section_alignment) (const struct ld_plugin_section section,
                                          unsigned int *addralign);

/* The linker's interface for retrieving the section size of a specific section
   in an object.  This interface should only be invoked in the claim_file handler.
   This function sets *SECSIZE to the ELF sh_size
   value of the input section.  */
enum ld_plugin_status
(*get_input_section_size) (const struct ld_plugin_section section,
                                     uint64_t *secsize);

/* Handlers that the linker lets us register. */

/* The plugin library's "claim file" handler.  */
struct claimed_file
{
	const struct ld_plugin_input_file *input_file;
	string name;
	vector<string> unbinds;
	
	claimed_file(const std::pair<const struct ld_plugin_input_file *, string> & p)
		: input_file(p.first), name(p.second) {}
};
static vector< claimed_file > claimed_files;
static vector< const struct ld_plugin_input_file * > input_files;
static vector< const struct ld_plugin_input_file * > input_files_needing_usedtypes;
static
enum ld_plugin_status
claim_file_handler (
  const struct ld_plugin_input_file *file, int *claimed)
{
	fprintf(stderr, "claim-file handler called (%s, currently %d)\n", file->name, *claimed);

	/* Don't claim any files if we're generating relocatable output.
	 * We only affect final links. */
	if (output_file_type == LDPO_REL) { *claimed = 0; return LDPS_OK; }
	
	/* If we "claim" a file, we are responsible for feeding its contents
	 * to the linker.
	 *
	 * How is this done in, say, the LLVM LTO plugin?
	 * In the claim-file hook, it just claims files and grabs input data.
	 * In the all-symbols-read hook, it creates lots of temporary files
	 * and does codegen. See below (in all_symbols_read_hook) for more on that.
	 */
	/* Which input files do we want to claim? Any .o file that needs tweaking.
	 * What tweaks does that include?
	 * 
	 * - uniqtype symbol renaming
	 * - allocator unbinding
	 * - allocator globalising
	 * - allocator definition __real_-aliasing (hmm, can do just with extra syms; need to claim?)
	 * 
	 * What about archives? Well, objcopy can handle them so I guess we treat
	 * them like .o files. But do we need any hacky exclusions for libgcc.a
	 * etc.? Or crt*.o? I suppose we shouldn't. */
	auto should_claim_or_needs_usedtypes = [file]() -> pair<bool, bool> {
		/* Things we can do in here: 

			(*get_input_section_count) (const void* handle, unsigned int *count);
			(*get_input_section_type) (const struct ld_plugin_section section,
												 unsigned int *type);
			(*get_input_section_name) (const struct ld_plugin_section section,
												 char **section_name_ptr);
			(*get_input_section_contents) (const struct ld_plugin_section section,
													 const unsigned char **section_contents,
													 size_t* len);
			(*update_section_order) (const struct ld_plugin_section *section_list,
							   unsigned int num_sections);
			(*allow_section_ordering) (void);
			(*allow_unique_segment_for_sections) (void);
			(*unique_segment_for_sections) (
				const char* segment_name,
				uint64_t segment_flags,
				uint64_t segment_alignment,
				const struct ld_plugin_section * section_list,
				unsigned int num_sections);
			(*get_input_section_alignment) (const struct ld_plugin_section section,
													  unsigned int *addralign);
			(*get_input_section_size) (const struct ld_plugin_section section,
												 uint64_t *secsize);

			... and possibly some others.
		*/
		/* How can we get the number of symbols? 
		 * We can't.
		 * As far as the linker is concerned, if we claim the file,
		 * there are no symbols except the ones we tell it about;
		 * it's our job to feed the linker symbols (now) and (later)
		 * sections!
		 * 
		 * Oh. But wait. What about the get_input_section_contents stuff?
		 * It sounds like it can walk the sections for us, just not
		 * the symbols. That's a bit odd. I suppose it allows ELF-packaging
		 * of other-format stuff, including intermediate symbol tables.
		 * So try: test whether it's a relocatable file, and if so, use
		 * the section calls to find the symtab.
		 */
		// auto ret = get_symbols(file, 0, nullptr);
		struct stat statbuf;
		int ret = fstat(file->fd, &statbuf);
		if (ret != 0) return make_pair(false, false);
#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif
		size_t mapping_size = ROUND_UP(statbuf.st_size, PAGE_SIZE);
		void *fmap = mmap(NULL, mapping_size, PROT_READ, MAP_PRIVATE,
			file->fd, file->offset);
		bool should_claim = false;
		bool needs_usedtypes = false;
		if (fmap != MAP_FAILED)
		{
			fprintf(stderr, "Mapped it at %p\n", fmap);
			Elf64_Ehdr *ehdr = (Elf64_Ehdr *) fmap;
			if (ehdr->e_ident[0] == '\177' && 
				ehdr->e_ident[1] == 'E' && 
				ehdr->e_ident[2] == 'L' && 
				ehdr->e_ident[3] == 'F' && 
				ehdr->e_ident[EI_CLASS] == ELFCLASS64 &&
				ehdr->e_ident[EI_DATA] == ELFDATA2LSB &&
				ehdr->e_type == ET_REL)
			{
				//fprintf(stderr, "We think `%s' is a relocatable 64-bit LSB object\n",
				//	file->name);
				/* Now we can use some of the linker functions. */
				/* Can we walk its symbols? */
				
				/* GAH. To get shdrs, need to do it ourselves. */
				const Elf64_Shdr *shdrs = reinterpret_cast<const Elf64_Shdr*>(
					(const unsigned char *) fmap + ehdr->e_shoff
				);
				unsigned section_count;
				int ret = get_input_section_count(file->handle, &section_count);
				if (ret == LDPS_OK)
				{
					//fprintf(stderr, "We think `%s' has %u sections\n",
					//	file->name, section_count);
					const char *strtab = nullptr;
					const Elf64_Sym *symtab = nullptr;
					unsigned symtab_shndx = 0;
					const Elf64_Sym *symtab_end = nullptr;
					for (unsigned i = 0; i < section_count; ++i)
					{
						const Elf64_Shdr *shdr = shdrs + i;
						unsigned int type;
						struct ld_plugin_section sect = {
							.handle = file->handle, .shndx = i
						};
						int ret = get_input_section_type(sect, &type);
						if (ret == LDPS_OK)
						{
							//fprintf(stderr, "We think section %u has type 0x%x\n",
							//	i, type);
							/* These are just ELF SHT_* values. So we care about
							 * the symtab and strtab. */
							const unsigned char *contents;
							size_t len;
							switch (type)
							{
								case SHT_SYMTAB: {
									ret = get_input_section_contents(sect, &contents,
										&len);
									if (ret == LDPS_OK)
									{
										/* We've got the symtab contents. */
										symtab = reinterpret_cast<const Elf64_Sym*>(contents);
										symtab_end = reinterpret_cast<const Elf64_Sym*>(contents)
											+ (len / sizeof (Elf64_Sym));
										symtab_shndx = i;
										/* Get the contents of the linked strtab too. */
										ret = get_input_section_contents(
											(struct ld_plugin_section) {
												.handle = file->handle,
												.shndx = shdr->sh_link
											}, &contents, &len);
										if (ret == 0) strtab = reinterpret_cast<const char *>(contents);
									}
								} break;
// 								case SHT_STRTAB:
// 									ret = get_input_section_contents(sect, &contents,
// 										&len);
// 									if (ret == LDPS_OK)
// 									{
// 										/* We've got the strtab. */
// 										strtab = reinterpret_cast<const char *>(contents);
// 									}
// 									break;
								default:
									
									break;
							} /* end switch */
						} /* end if ret == ok */
					} /* end for each section */
					if (symtab && symtab_end && strtab)
					{
						/* FIXME: it's not whether it has a wrapped symbol that matters. 
						 * It's whether it needs unbinding, globalizing or
						 * aliases defined. */
						auto found_defined = defined_symbols_matching(
							symtab, symtab_end, strtab,
							wrapped_sym_names
						);
						//for (string s : found)
						//{
						//	fprintf(stderr, "saw an interesting function: %s\n",
						//		s.c_str());
						//}
						if (found_defined.size() > 0)
						{
							should_claim = true;
						}
						auto found_undefined = undefined_symbols_matching(
							symtab, symtab_end, strtab,
							vector<string>(1, "__uniqtype_.*")
						);
						//for (string s : found)
						//{
						//	fprintf(stderr, "saw an interesting function: %s\n",
						//		s.c_str());
						//}
						if (found_undefined.size() > 0)
						{
							needs_usedtypes = true;
						}						
						
					}
				} /* end if ret ok */
			} /* end if is an interesting ELF file */
			
			munmap(fmap, mapping_size);
		}
	
		return make_pair(should_claim, needs_usedtypes);
	};
	
	input_files.push_back(file);
	auto verdict = should_claim_or_needs_usedtypes();
	bool should_claim = verdict.first;
	bool needs_usedtypes = verdict.second;
	if (needs_usedtypes) input_files_needing_usedtypes.push_back(file);
	if (should_claim)
	{
		*claimed = 1;
		auto tmpfile = new_temp_file("allocplugin");
		string tmpname = tmpfile.first;
		int tmpfd = tmpfile.second;
		if (tmpfd == -1) abort();
		fprintf(stderr, "Claimed file is replaced by temporary %s\n", tmpname.c_str());
		int ret = ftruncate(tmpfd, file->filesize);
		if (ret != 0) abort();
		void *dst_mapping = mmap(NULL, ROUND_UP(file->filesize, PAGE_SIZE),
			PROT_READ|PROT_WRITE, MAP_SHARED, tmpfd, 0);
		if (dst_mapping == MAP_FAILED) abort();
		
		size_t page_boundary_delta = file->offset - ROUND_DOWN(file->offset, PAGE_SIZE);
		size_t src_mapping_len = ROUND_UP(file->offset + file->filesize, PAGE_SIZE)
			- ROUND_DOWN(file->offset, PAGE_SIZE);
		void *src_mapping_raw = mmap(NULL, src_mapping_len,
			PROT_READ, MAP_PRIVATE, file->fd, 
			ROUND_DOWN(file->offset, PAGE_SIZE));
		if (src_mapping_raw == MAP_FAILED) abort();
		void *src_mapping = (unsigned char *) src_mapping_raw + page_boundary_delta;

// 		off_t initial_offset = lseek(file->fd, 0, SEEK_CUR);
// 		lseek(file->fd, file->offset, SEEK_SET);
// 		/* K&R-style copy file */
// 		const int bufsz = 65536;
// 		char copybuf[bufsz];
// 		size_t size;
// 		size_t copied = 0;
// 		/* Avoid extra buffering in the copy I/O. FIXME: 
// 		 * do all this by memcpy / mmap, above -- return an opt<string>
// 		 * containing the temp filename. */
// 		while (0 <= (size = read(file->fd, copybuf, bufsz))) {
// 			write(tmpfd, copybuf, size);
// 			copied += size;
// 			if (copied >= file->filesize) break; // FIXME: exploiting that ELFs can contain junk at end
// 		}
// 		close(tmpfd);
// 		/* Return the file pointer to its original position. */
// 		lseek(file->fd, initial_offset, SEEK_SET);
		memcpy(dst_mapping, src_mapping, file->filesize);
		munmap(src_mapping_raw, src_mapping_len);
		munmap(dst_mapping, file->filesize);
		close(tmpfd);
		
		claimed_files.push_back(make_pair(file, tmpname));
	}
	
	return LDPS_OK;
}
/* Okay. What do we need to do with this file? */
static void do_unbind(claimed_file& f, const vector<string>& u)
{
	/* FIXME: can we use llvm objcopy as a library? */
	
	// make a backup copy
	auto tmpfile = new_temp_file(string("preunbind.") + basename((char*)f.name.c_str()));
	int ret = system(("cp '" + f.name + "' '" + tmpfile.first + "'").c_str());
	if (ret) abort();
	
	// do the unbind -- we get a __def_ and __ref_ for each defined wrapped fn
	// bit of a HACK: also do globalize at the same time
	string cmd = "objcopy --prefer-non-section-relocs";
	for (auto sym : u) cmd += (" --globalize-sym '" + sym + "' --unbind-sym '" + sym + "'");
	cmd += (" " + f.name);
	ret = system(cmd.c_str());
	if (ret) abort();
	
	// point the references instead at __wrap_
	cmd = "objcopy --prefer-non-section-relocs";
	for (auto sym : u) cmd += (" --redefine-sym __ref_" + sym + "=__wrap_" + sym);
	cmd += f.name;
	ret = system(cmd.c_str());
	
	// alias __def_X as both __real_X and plain unprefixed X
	// -- the __real_ is looked up preferentially by mallochooks fake_dlsym code
	// -- the unprefixed is so that uninstrumented calls hit the callee stub (FIXME: CHECK)
	auto tmpfile2 = new_temp_file(string("preunbinddefsym.") + basename((char*)f.name.c_str()));
	ret = system(("mv '" + f.name + "' '" + tmpfile2.first + "'").c_str());
	if (ret) abort();
	cmd = "ld -r -o '" + f.name + "' '" + tmpfile2.first + "'";
	for (auto sym : u) cmd += (" --defsym " + sym + "=__def_" + sym + 
		" --defsym __real_" + sym + "=__def_" + sym);
	ret = system(cmd.c_str());
	if (ret) abort();
}

static void do_link_used_types(const ld_plugin_input_file *pf)
{
	/* Here we are actually adding content. So just add each object's
	 * usedtypes as a new input object to the link. The difference between 
	 * usedtypes and other ("meta") types is that those that are used
	 * really need to be added to the (non-separable) core link job. */
	auto src_tmpfile = new_temp_file("usedtypes.src");
	string src_tmpfilename = src_tmpfile.first;
	//int tmpfd = tmpfile.second;
	//sstream 
	std::ofstream of(src_tmpfilename);
	if (!of) abort();
	int ret = //system(("usedtypes '" + string(pf->name) + "' > '" + tmpfilename + "'").c_str());
		dump_usedtypes(vector<string>(1, string(pf->name)), of, std::cerr);
	if (ret == 0)
	{
		// compile it
		auto obj_tmpfile = new_temp_file("usedtypes.obj");
		ret = system(("/usr/bin/cc -fPIC -c '" + src_tmpfilename + "' -o '" + obj_tmpfile.first + "'").c_str());
		if (ret != 0) abort();
		add_input_file(obj_tmpfile.first.c_str());
	}
	else {} // FIXME: better diagnostics
}

static optional<string> stubs;
static optional<string> meta;

optional<string> generate_allocator_stubs_object()
{
	return optional<string>();
}

optional<string> generate_meta_object()
{
	return optional<string>();
}

/* The plugin library's "all symbols read" handler.  */
static
enum ld_plugin_status
all_symbols_read_handler (void)
{
	fprintf(stderr, "all-symbols-read handler called ()\n");
	/* How is this done in, say, the LLVM LTO plugin?
	 * In the claim-file hook, it just claims files and grabs input data.
	 * In the all-symbols-read hook, it creates lots of temporary files
	 *  and does codegen.
	 * How does it feed the generated code back to the linker?
	 * It generates temporary object files and uses add_input_file()
	 * to add them to the link.
	 */
	
	/* Things we can do in here:
	/* 
		(*add_symbols) (void *handle, int nsyms,
                        		  const struct ld_plugin_symbol *syms);

		(*get_input_file) (const void *handle,
                            		 struct ld_plugin_input_file *file);

		(*get_view) (const void *handle, const void **viewp);

		(*release_input_file) (const void *handle);

		(*get_symbols) (const void *handle, int nsyms,
                        		  struct ld_plugin_symbol *syms);

		(*add_input_file) (const char *pathname);

		(*add_input_library) (const char *libname);
	 */
	
	for (auto p : claimed_files)
	{
		/* Okay. What do we need to do with this file? */
		if (p.unbinds.size() > 0) do_unbind(p, p.unbinds);
		
		add_input_file(p.name.c_str());
	}
	
	for (auto pf : input_files_needing_usedtypes)
	{
		/* For the used types, we have a problem: don't want
		 * undefined references. */
		do_link_used_types(pf);
	}
	
	/* Also add the extra input files. */
	stubs = generate_allocator_stubs_object();
	if (stubs) add_input_file(stubs->c_str());
	meta = generate_meta_object();
	if (meta) add_input_file(meta->c_str());
	
	return LDPS_OK;
}

/* The plugin library's cleanup handler.  */
static void hack_output_file_with_meta_phdrs()
{

}

static
enum ld_plugin_status
cleanup_handler (void)
{
	fprintf(stderr, "cleanup handler called ()\n");
	
	for (auto p : claimed_files)
	{
		release_input_file(p.input_file);
	}
	
	for (string s : temp_files_to_unlink)
	{
		unlink(s.c_str());
	}
	
	if (meta)
	{
		hack_output_file_with_meta_phdrs();
	}
	
	return LDPS_OK;
}

/* Linker interfaces: hook registration. */

/* The linker's interface for registering the "claim file" handler.  */
enum ld_plugin_status
(*register_claim_file) (ld_plugin_claim_file_handler handler);
/* The linker's interface for registering the "all symbols read" handler.  */
enum ld_plugin_status
(*register_all_symbols_read) (
  ld_plugin_all_symbols_read_handler handler);
/* The linker's interface for registering the cleanup handler.  */
enum ld_plugin_status
(*register_cleanup) (ld_plugin_cleanup_handler handler);

/* The plugin library's "onload" entry point.  */
extern "C" {
enum ld_plugin_status
onload(struct ld_plugin_tv *tv);
}
enum ld_plugin_status
onload(struct ld_plugin_tv *tv)
{
	// for debugging
	if (getenv("LD_DELAY_STARTUP"))
	{
		fprintf(stderr, "Hello from linker plugin, in pid %d\n", getpid());
		fflush(stderr);
		sleep(12);
	}

#define CASE(x) \
	case LDPT_ ## x: fprintf(stderr, "Transfer vector contained LDPT_" #x ", arg %p\n", i_tv->tv_u.tv_string); break;
#define CASE_INT(x, dest) \
	case LDPT_ ## x: fprintf(stderr, "Transfer vector contained LDPT_" #x ", arg %d\n", i_tv->tv_u.tv_val); dest = i_tv->tv_u.tv_val; break;
#define CASE_STRING(x) \
	case LDPT_ ## x: fprintf(stderr, "Transfer vector contained LDPT_" #x ", arg `%s'\n", i_tv->tv_u.tv_string); break;
#define CASE_FP(x, lc) \
	case LDPT_ ## x: fprintf(stderr, "Transfer vector contained LDPT_" #x "; argument %p\n", \
	    i_tv->tv_u.tv_ ## lc); \
	lc = static_cast<__typeof(lc)>(i_tv->tv_u.tv_ ## lc); \
	break;
#define CASE_FP_REGISTER(x, lc) \
	case LDPT_REGISTER_ ## x: fprintf(stderr, "Transfer vector contained LDPT_REGISTER_" #x "; argument %p\n", \
	    i_tv->tv_u.tv_register_ ## lc); \
	register_ ## lc = static_cast<__typeof(register_ ## lc)>(i_tv->tv_u.tv_register_ ## lc); \
	break;
	for (struct ld_plugin_tv *i_tv = tv; i_tv->tv_tag != LDPT_NULL; ++i_tv)
	{
		switch (i_tv->tv_tag)
		{
			CASE(NULL)
			CASE_INT(API_VERSION, api_version)
			CASE_INT(GOLD_VERSION, gold_version)
			CASE_INT(LINKER_OUTPUT, output_file_type)
			CASE_STRING(OPTION)
			CASE_FP_REGISTER(CLAIM_FILE_HOOK, claim_file)
			CASE_FP_REGISTER(ALL_SYMBOLS_READ_HOOK, all_symbols_read)
			CASE_FP_REGISTER(CLEANUP_HOOK, cleanup)
			CASE_FP(ADD_SYMBOLS, add_symbols)
			CASE_FP(GET_SYMBOLS, get_symbols)
			CASE_FP(ADD_INPUT_FILE, add_input_file)
			CASE_FP(MESSAGE, message)
			CASE_FP(GET_INPUT_FILE, get_input_file)
			CASE_FP(RELEASE_INPUT_FILE, release_input_file)
			CASE_FP(ADD_INPUT_LIBRARY, add_input_library)
			CASE_STRING(OUTPUT_NAME)
			CASE_FP(SET_EXTRA_LIBRARY_PATH, set_extra_library_path)
			CASE_INT(GNU_LD_VERSION, gnu_ld_version)
			CASE_FP(GET_VIEW, get_view)
			CASE_FP(GET_INPUT_SECTION_COUNT, get_input_section_count)
			CASE_FP(GET_INPUT_SECTION_TYPE, get_input_section_type)
			CASE_FP(GET_INPUT_SECTION_NAME, get_input_section_name)
			CASE_FP(GET_INPUT_SECTION_CONTENTS, get_input_section_contents)
			CASE_FP(UPDATE_SECTION_ORDER, update_section_order)
			CASE_FP(ALLOW_SECTION_ORDERING, allow_section_ordering)
			CASE_FP(GET_SYMBOLS_V2, get_symbols)
			CASE_FP(ALLOW_UNIQUE_SEGMENT_FOR_SECTIONS, allow_unique_segment_for_sections)
			CASE_FP(UNIQUE_SEGMENT_FOR_SECTIONS, unique_segment_for_sections)
			CASE(GET_SYMBOLS_V3)
			CASE_FP(GET_INPUT_SECTION_ALIGNMENT, get_input_section_alignment)
			CASE_FP(GET_INPUT_SECTION_SIZE, get_input_section_size)
			default:
				fprintf(stderr, "Did not recognise transfer vector element %d\n", 
					(int) i_tv->tv_tag);
				break;
		}
	}
	
	if (register_claim_file) register_claim_file(claim_file_handler);
	if (register_all_symbols_read) register_all_symbols_read(all_symbols_read_handler);
	if (register_cleanup) register_cleanup(cleanup_handler);
	
	/* Do our local initialization. */
	wrapped_sym_names = all_wrapped_sym_names();
	free_fns = all_free_fns();
	
	return LDPS_OK;
}

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
 * 
 * We use both liballocstool and LLVM APIs in this file. There's
 * no easy way that either can be eliminated, except in the very
 * long run perhaps. Style-wise, it's easier for me to use my own
 * style.
 */

#include <vector>
#include <string>
#include <regex>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <sys/mman.h>
#include <elf.h>
#include <cassert>
#include "plugin-api.h"
#define RELF_DEFINE_STRUCTURES 1
#include "relf.h" /* to get our own binary's realpath -- bit of a HACK */
#include <libgen.h> /* for dirname() */
#include <unistd.h> /* for sleep() */

using std::vector;
using std::string;
using std::smatch;
using std::regex;
using std::regex_match;

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
vector<string>
all_wrapped_sym_names()
{
	vector<string> out;
	for (string alloc_fn : all_alloc_fns())
	{
		if (alloc_fn == "") continue;
		smatch m;
		if (regex_match(alloc_fn, m, regex("(.*)\((.*)\)(.?)")))
		{
			out.push_back(m[0]);
		}
	}
	for (string free_fn : all_sub_free_fns())
	{
		if (free_fn == "") continue;
		smatch m;
		if (regex_match(free_fn, m, regex("(.*)\((.*)\)(.?)")))
		{
			out.push_back(m[0]);
		}
	}
	for (string free_fn : all_l1_free_fns())
	{
		if (free_fn == "") continue;
		smatch m;
		if (regex_match(free_fn, m, regex("(.*)\((.*)\)")))
		{
			out.push_back(m[0]);
		}
	}
	return out;
}
string::const_iterator
find_first_upper_case(const string& s)
{
	for (auto i_c = s.begin(); i_c != s.end(); ++i_c)
	{
		if (isupper(*i_c)) return i_c;
	}
	return s.end();
}
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
vector<string>
defined_symbols_matching(void *fixme_lib_handle, const vector<string>& patterns)
{
	/*
    def listDefinedSymbolsMatching(self, filename, patterns, errfile=None):
        with (self.makeErrFile(os.path.realpath(filename) + ".fixuplog", "w+") if not errfile else errfile) as errfile:
            regex = "|".join(patterns)
            self.debugMsg("Looking for defined functions matching `%s'\n" % regex)
            cmdstring = "nm -fbsd \"%s\" | grep -v '^[0-9a-f ]\+ U ' | egrep \"^[0-9a-f ]+ . (%s)$\" | sed 's/^[0-9a-f ]\+ . //'" \
                % (filename, regex)
            self.debugMsg("cmdstring for objdump is " + cmdstring + "\n")
            grep_output = subprocess.Popen(["sh", "-c", cmdstring], stdout=subprocess.PIPE, stderr=errfile).communicate()[0]
            return [l for l in grep_output.split("\n") if l != '']
	*/
	
	assert(false);
}
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
static vector<const struct ld_plugin_input_file *> claimed_files;
static
enum ld_plugin_status
claim_file_handler (
  const struct ld_plugin_input_file *file, int *claimed)
{
	fprintf(stderr, "claim-file handler called (%s, currently %d)\n", file->name, *claimed);
	
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
	 * - allocator definition __real_-aliasing (hmm, can do just with extra syms)
	 * 
	 * What about archives? Well, objcopy can handle them so I guess we treat
	 * them like .o files. But do we need any hacky exclusions for libgcc.a
	 * etc.? Or crt*.o? I suppose we shouldn't. */
	auto should_claim = [file]() {
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
		void *first_page = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, file->fd, file->offset);
		if (first_page != MAP_FAILED)
		{
			fprintf(stderr, "Mapped it at %p\n", first_page);
			Elf64_Ehdr *ehdr = (Elf64_Ehdr *) first_page;
			if (ehdr->e_ident[0] == '\177' && 
				ehdr->e_ident[1] == 'E' && 
				ehdr->e_ident[2] == 'L' && 
				ehdr->e_ident[3] == 'F' && 
				ehdr->e_ident[EI_CLASS] == ELFCLASS64 &&
				ehdr->e_ident[EI_DATA] == ELFDATA2LSB &&
				ehdr->e_type == ET_REL)
			{
				fprintf(stderr, "We think `%s' is a relocatable 64-bit LSB object\n",
					file->name);
				/* Can we walk its symbols? */
				
				
				unsigned section_count;
				int ret = get_input_section_count(file->handle, &section_count);
				if (ret == LDPS_OK)
				{
					fprintf(stderr, "We think `%s' has %u sections\n",
						file->name, section_count);
					for (unsigned i = 0; i < section_count; ++i)
					{
						unsigned int type;
						int ret = get_input_section_type(
							(struct ld_plugin_section) { .handle = file->handle, .shndx = i },
							&type);
						if (ret == LDPS_OK)
						{
							fprintf(stderr, "We think section %u has type 0x%x\n",
								i, type);
						}
					}
				}
			}
			
			munmap(first_page, 4096);
		}
	
		return false;
	};
	
	if (should_claim())
	{
		*claimed = 1;
		claimed_files.push_back(file);
	}
	
	return LDPS_OK;
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
	
	return LDPS_OK;
}

/* The plugin library's cleanup handler.  */
static
enum ld_plugin_status
cleanup_handler (void)
{
	fprintf(stderr, "cleanup handler called ()\n");
	
	for (const void *handle : claimed_files)
	{
		release_input_file(handle);
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
	fprintf(stderr, "Hello from linker plugin, in pid %d\n", getpid());
	fflush(stderr);
	// for debugging
	if (getenv("LD_DELAY_STARTUP")) sleep(12);

#define CASE(x) \
	case LDPT_ ## x: fprintf(stderr, "Transfer vector contained LDPT_" #x ", arg %p\n", i_tv->tv_u.tv_string); break;
#define CASE_INT(x) \
	case LDPT_ ## x: fprintf(stderr, "Transfer vector contained LDPT_" #x ", arg %d\n", i_tv->tv_u.tv_val); break;
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
			CASE_INT(API_VERSION)
			CASE_INT(GOLD_VERSION)
			CASE_INT(LINKER_OUTPUT)
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
			CASE_INT(GNU_LD_VERSION)
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
	
	return LDPS_OK;
}

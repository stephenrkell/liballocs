/* Linker plugin for liballocs.
 * 
 * Copyright 2017, 2022 Stephen Kell <stephen.kell@cl.cam.ac.uk>
 * 
 * This replaces various logic of allocscompilerwrapper.py:
 * - calling link-used-types to generate uniqtypes
 * - allocator instrumentation (generateAllocatorMods)
 * - globalizing any allocator functions that are currently local symbols
        (named by a dwarfidl-esque pathname?
         using '::', then globalize under a fresh, generated name)
 * - if we change the name during globalization, we have to feed it forward
 *      to the xwrap plugin, unless it's a deterministic function of the name
 *    ** can we just get the xwrap plugin to do this? no because it's generic
 *
 * Because the GNU plugin API does not currently give us control of everything
 * that the linker command line can control, we rely on techniques that are a
 * bit nasty. In particular, we restart the link with additional/changed command-
 * -line options. Those options include adding new plugins! In particular, for
 * symbol wrapping we use our own 'xwrap-plugin' which is a higher-coverage
 * version of ld's --wrap option.
 */
#define _GNU_SOURCE
#include <vector>
#include <string>
#include <regex>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#ifdef _LIBGEN_H
#error "We require GNU basename(), so please don't include libgen.h"
#endif
#include <cstring>
#include <sys/mman.h>
#include <elf.h>
#include <cassert>
#include <unistd.h> /* for sleep() */
#include <boost/algorithm/string.hpp> /* for split, is_any_of */
#include <sys/types.h> /* for fstat() */
#include <sys/stat.h> /* for fstat() */
#include <unistd.h> /* for fstat(), write(), read() */
#include <utility> /* for pair */
#include <boost/filesystem.hpp>
extern "C" {
#include <link.h>
}
#include "uniqtypes.hpp"
#include "relf.h" /* to get our own binary's realpath -- bit of a HACK */

#include "elftin/ldplugins/plugin-api.hh"
#include "elftin/ldplugins/base-ldplugin.hh"
#include "elftin/ldplugins/restart-self.hh"
#include "elftin/ldplugins/cmdline.hh"

using std::vector;
using std::string;
using std::smatch;
using std::regex;
using std::regex_match;
using std::pair;
using std::make_pair;
using std::optional;

using namespace allocs::tool;
using namespace elftin;

struct allocs_plugin : elftin::linker_plugin
{
	string alloc_fns;
	string free_fns;
	string allocsz_fns;
	string suballoc_fns;
	string subfree_fns;
	string allocsite_overrides;
private:
	// populated from environment variables
	set<string> global_symnames_of_interest;
	set< pair< string, string> > file_and_local_symname_pairs_of_interest;

	// populated by intersecting 'of interest' with actually found in inputs
	map< pair<string, off_t> , set<string> > file_and_local_symname_pairs_to_globalize; // those we found
	map< pair<string, off_t> , set<string> > global_symnames_to_xwrap_by_input_file;
	set<string> global_symnames_to_xwrap;
	std::optional<string> saw_malloc; // do we define 'malloc'?
public:
	/* The plugin library's "claim file" handler. */
	enum ld_plugin_status
	claim_file(const struct ld_plugin_input_file *file, int *claimed)
	{
		/* Is this a filename that we need to globalize? And does it
		 * contain a local symbol of the expected name? (For each expected
		 * name, since there may be many.) */
		bool should_claim = false;
		// does this file have an entry in the map?
		auto& this_file_symnames
		 = file_and_local_symname_pairs_to_globalize[make_pair(string(file->name), file->offset)];
		if (this_file_symnames.size() != 0)
		{
			*claimed = 1;
			if (file->offset != 0)
			{
				linker->message(LDPL_ERROR, "FIXME: don't know how to globalize within archive member");
				abort();
			}
			auto obj_tmpfile = new_temp_file("globalized.obj");
			linker->add_input_file(obj_tmpfile.first.c_str());
			/* FIXME: create elftin tools/libs for this so we don't have to shell out */
			string cmd = "objcopy ";
			// Rename at the same time as globalizing
			// ... then add the renamed symbol to the list of global symbols of interest
			for (auto sym : this_file_symnames)
			{
				string new_symname = "__allocs_globalized_" + mangle_string(
						basename(/* OK with GNU basename */(char*)file->name)
					) + "_" + sym;
				cmd += (string("--redefine-sym '") + sym
					+ "=" + new_symname + "' ");
				cmd += (string("--globalize-sym '") + sym + "' ");
				global_symnames_to_xwrap.insert(new_symname);
			}
			cmd += (string(" ") + file->name) + obj_tmpfile.first;
			int ret = system(cmd.c_str());
			if (ret != 0)
			{
				linker->message(LDPL_ERROR, "globalizing (%s): objcopy returned %d", file->name, ret);
				abort();
			}
		} else *claimed = 0;
		enum ld_plugin_status super_ret = this->linker_plugin::claim_file(file, claimed);
		if (super_ret != LDPS_OK) return super_ret;
		return LDPS_OK;
	}

	static string shell_quote(const string& s)
	{
		/* We use single quotes. If the arg contains a single quote,
		 * turn it into the string '"'"' */
		string copy = s;
		auto i_pos = copy.begin();
		while (i_pos != copy.end())
		{
			if (*i_pos == '\'')
			{
				i_pos = copy.erase(i_pos);
				static const string replacement = "'\"'\"'";
				auto inserted = copy.insert(i_pos, replacement.begin(), replacement.end());
				i_pos = inserted + (replacement.end() - replacement.begin());
			}
			else ++i_pos;
		}
		return string("'") + copy + "'";
	}

	static string wordify(const string& s, char macro_name = 'w');

	int compile_c_source_and_add_as_input(string const& src_tmpfilename,
			const string& label,
			const string& insert = "",
			bool quote_src_tmpfilename = true)
	{
		// compile it
		auto obj_tmpfile = new_temp_file(label + ".obj");
		int ret = system((string("${META_CC:-cc} ") + insert + "-std=c11"
			+ " ${META_CFLAGS:-${LIBALLOCSTOOL:+-I${LIBALLOCSTOOL}/include}} -fPIC -c -x c "
			+ (quote_src_tmpfilename ? "'" : "") + src_tmpfilename + (quote_src_tmpfilename ? "'" : "") + " -o '" + obj_tmpfile.first + "'").c_str());
		if (ret != 0)
		{
			linker->message(LDPL_ERROR, (label + " cc command returned %d").c_str(), ret);
			return LDPS_ERR;
		}
		// don't add a zero-length file
		struct stat st;
		ret = stat(obj_tmpfile.first.c_str(), &st);
		if (ret != 0)
		{		
			linker->message(LDPL_ERROR,
				(string("could not stat ") + label + " output file: %s").c_str(),
				strerror(ret));
			return LDPS_ERR;
		}
		if (st.st_size > 0)
		{
			linker->add_input_file(obj_tmpfile.first.c_str());
			return LDPS_OK;
		}
		return LDPS_OK;
	}

	enum ld_plugin_status
	all_symbols_read()
	{
		/* Finally, add the dummyweaks library. This should go away; see GitHub issue #56.
		 * Conceptually we want to do this in our constructor, but that's too soon for
		 * gold (it crashes if we call add_input_library so soon). */
		if (job->output_file_type != LDPO_REL)
		{
			linker->add_input_library("allocs_dummyweaks");
		}
		/* If we're using allocsld, or might be, we need to add the interp-pad.o to the
		 * link to ensure allocsld can overwrite the .interp string during chain loading.
		 * This is a nasty HACK and should probably go away or be refined somehow
		 * (for ideas: https://www.humprog.org/~stephen/blog/devel/#elf-chain-loading) .*/
		if (job->output_file_type == LDPO_PIE || job->output_file_type == LDPO_EXEC)
		{
			linker->add_input_file(
				(boost::filesystem::path(getenv("LIBALLOCS")?:"") / "lib/interp-pad.o").c_str()
			);
		}

		// -1. assume that undefined uniqtype symnames have been renamed
		//             from C-style to accurate ones, using the DWARF
		//         -- this needs to be a separate pass over .o files generated from C compilation jobs
		//         -- is this easy to do with toolsub?
		//            we can even perhaps *assume* we're compiling C, in a -cflags
		//    ... the logic is just objcopy_and_redefine_c_names from tools/lang/c/bin/link-used-types
		//    ... one problem with current handling is that it breaks e.g. if a struct is named
		//        'unsigned_long' etc.
		// 0. generate+add the usedtypes file. Input: list of undefined __uniqtype_* symbols
		// 1. ASSUME ALREADY DONE (by claim-file): globalize any allocation functions identified as static symbols
		// 2. add xwrap-ldplugin, giving it as an option with the list of 'self.allWrappedSymNames()' (allAllocFns + allFreeFns)
		// 3. generate+add the allocstubs file, containing a gaggle of cases
		//         (caller-side, callee-side if malloc is present,
		//         combo for 'deep' suballocators)
		
		
		/* Can we do usedtypes for a whole link, not each file?
		 * Need 'usedtypes' to take many files on the command line.
		 * Which it does! */
		auto src_tmpfile = new_temp_file("usedtypes.src");
		string src_tmpfilename = src_tmpfile.first;
		std::ofstream of(src_tmpfilename);
		if (!of) abort();
		/* Can we get the linker to enumerate all input .o files?
		 * It needs to include any claimed file that we substituted.
		 * Sadly the answer seems to be no, out of the box. So I've
		 * modified base-ldplugin so that it keeps track of input
		 * files, by remembering the claim_file calls. And I've modified
		 * the linker to remember the add_input_file calls. PROBLEM:
		 * what about other plugins that claim files and add inputs
		 * without our knowledge? */
		/* What about archives? If usedtypes supports them
		 * then it's no problem. It doesn't, but let's not worry here.
		 * Actually archives are interesting: we want to do usedtypes
		 * only for any archive members that are being pulled in, but
		 * not otherwise. So maybe we need to support the 'archive.a(file.o)'
		 * syntax on its command line. */
		set<string> included_input_files;
		for (auto& pair : job->input_files)
		{
			auto& bytes = pair.second.second;
			debug_println(0, "%s %u %d %d %02x", pair.first.first.c_str(), (unsigned) pair.first.second,
				(int) pair.second.first, (int) bytes.size(),
				(unsigned) (bytes.size() > 0) ? bytes[0] : 0xff );
			// we only want the REL files, i.e. stuff that is going in to our link
			if (bytes.size() == 64 &&
				0 == memcmp(&bytes[0], "\x7f""ELF", 4) &&
				reinterpret_cast<ElfW(Ehdr) *>(&bytes[0])->e_type == ET_REL
			)
			{
				included_input_files.insert(pair.first.first);
			}
		}
		int ret = 0;
		vector<string> cmd_args;
		for (string f : included_input_files) cmd_args.push_back(f);
		/* FIXME: libify 'usedtypes' so we don't have to shell out. */
		string cmd = "\"${USEDTYPES:-$(which usedtypes || echo ${LIBALLOCS}/tools/usedtypes)}\"";
		debug_println(0, "cmd starts %s", cmd.c_str());
		for (string arg : cmd_args) cmd = cmd + " " + shell_quote(arg);
		cmd = cmd + " > " + shell_quote(src_tmpfile.first);
		debug_println(0, "cmd is `%s'", cmd.c_str());
		ret = system(cmd.c_str());
		if (ret != 0)
		{
			linker->message(LDPL_ERROR, "usedtypes command returned %d", ret);
			abort();
		}
		ret = compile_c_source_and_add_as_input(src_tmpfile.first,
			string("usedtypes"));
		if (ret != LDPS_OK) abort();

		/* FIXME: in the below we should really prune_and_wordify, where
		 * pruning removes any entry if the corresponding symbol is
		 * not defined in the link. If we don't do this, we risk
		 * undefined reference link errors from our allocstubs.o. */
		 /* We unconditionally build and link the allocstubs file. We are
		  * relying on the preprocessor environment controlling the expansion of
		  * macros therein such that only the needed stubs are generated.
		  * */
		debug_println(0, "for malloc stubs, saw malloc? %s", (!saw_malloc) ? "no" : saw_malloc->c_str());
		ret = compile_c_source_and_add_as_input(string("\"${LIBALLOCS:+${LIBALLOCS}/tools/}allocstubs.c\""),
			string("allocstubs"),
			(string(/* for debugging */ string("-save-temps "/*"-Wp,-dD"*/) +
			/* insert the CFLAGS for our six arguments */
			" -DLIBALLOCS_ALLOC_FNS\"(w)\"=\"" + wordify(alloc_fns) + "\"" +
			" -DLIBALLOCS_FREE_FNS\"(w)\"=\"" + wordify(free_fns) + "\"" +
			" -DLIBALLOCS_ALLOCSZ_FNS\"(w)\"=\"" + wordify(allocsz_fns) + "\"" +
			" -DLIBALLOCS_SUBALLOC_FNS\"(w)\"=\"" + wordify(suballoc_fns) + "\"" +
			" -DLIBALLOCS_SUBFREE_FNS\"(w)\"=\"" + wordify(subfree_fns) + "\"" +
			" -DLIBALLOCS_ALLOCSITE_OVERRIDE\"(w)\"=\"" + wordify(allocsite_overrides) + "\"" +
			/* have we seen 'malloc' being defined in an input REL? */
			(saw_malloc ? " -DLIBALLOCS_MALLOC_CALLEE_WRAPPERS " : "")
			).c_str()), /* quote src filename? */ false);
		if (ret != LDPS_OK) abort(); /* compile_c_source_and_add_as_input() has printed error */

		 
		/* HACK: if we've added stuff that depends on TLS, we may need to bump
		 * the dynamic linker -- does this work?!?! Yes, seems to.
		 * FIXME: this makes me think that a linker plugin is a bad idea and we 
		 * should instead have stuck with wrapper scripts. Big problem with my
		 * self-rebuilding C approach is: how do we extend it allowing use of
		 * existing functions, like we currently do
		 * using 'source' ? I guess we can #include ? but omit the main()? or #define main to
		 * orig_main or something? */
		linker->add_input_file("/lib64/ld-linux-x86-64.so.2");

		// now just do the super call for good measure
		return this->linker_plugin::all_symbols_read();
	}
private:
	/* Our regexes are really 'static', but we can't initialize them
	 * here if we make them static -- needs to go outside the class.
	 * We could make them non-static and initialize them here, but
	 * the order of initialization would be unspecified, and we have
	 * interreference. So capture them in a macro. */
	/* Note that as separators we match either ',' or ';', so that
	 * we can use the same regexes before or after we replace ';' with ','. */
#define regexes(v) \
   v(ident, "([a-zA-Z_][a-zA-Z0-9_[:blank:]:]*)") \
   v(tuple, "\\([a-zA-Z]([;,][a-zA-Z])*\\)") \
   v(suffix, "((->)?[a-zA-Z])?") \
   v(one_entry, "(" + ident_re_s + "[;,]" + tuple_re_s + "[;,]" + suffix_re_s + ")") \
   v(whole_var, string("(") + one_entry_re_s + "([[:blank:]]+" + one_entry_re_s + ")*)?") \
   v(ws, "[[:blank:]]+")
   /* Note the naming convention here: the string gets 'ident'_re_s,
    * the regex is 'ident'_re. */
#define declare_regex(name, contents) \
    static string name ## _re_s; \
    static std::regex name ## _re;
	regexes(declare_regex)

	static void init_regexes()
	{
		bool run = false;
		if (!run)
		{
			run = true;
#define init_regex(name, contents) \
        name ## _re_s = contents; \
        name ## _re = std::regex(name ## _re_s);
			regexes(init_regex)
		}
	}
	string check_and_rewrite(const string& in)
	{
		/* CHECK all our _fns strings match a basic regex. We will use
		 * this regex to extract the symnames from each. In our regex,
		 * symnames can contain horizontal whitespace and ':' characters. */
		std::smatch m;
		if (!regex_match(in, m, whole_var_re))
		{
			linker->message(LDPL_ERROR, "allocs linker plugin options 1--6 must match regex `%s', e.g. `malloc;(Z);p realloc;(p;Z);p calloc;(z;Z);p'; got: `%s'",
				whole_var_re_s.c_str(), in.c_str());
			abort();
		}
		// now replace ';' with ',' so that they are cppable. we do the
		// 'wordification' separately
		string out = in;
		std::replace(out.begin(), out.end(), ';', ',');
		return out;	
	}

	set<string> extract_idents(const string& in)
	{
		set<string> ret;
		std::sregex_token_iterator begin(in.begin(), in.end(), ws_re, -1), end;
		for (auto i = begin; i != end; ++i)
		{
			string entry = *i;
			std::smatch im;
			bool found = regex_match(entry, im, std::regex(ident_re_s + ".*"));
			if (found)
			{
				string ident = im[1];
				ret.insert(ident);
			}
		}
		return ret;
	}
public:
	allocs_plugin(struct ld_plugin_tv *tv) : linker_plugin(tv),
		alloc_fns( /* shoe-horn in an error/crash if too few arguments were specified */
			(((job->options.size() < 5) ?
				(linker->message(LDPL_ERROR, "requires exactly 6 options"), abort(), 0): 0),
				init_regexes(),
			check_and_rewrite(job->options.at(0)))),
		free_fns(check_and_rewrite(job->options.at(1))),
		allocsz_fns(check_and_rewrite(job->options.at(2))),
		suballoc_fns(check_and_rewrite(job->options.at(3))),
		subfree_fns(check_and_rewrite(job->options.at(4))),
		allocsite_overrides(check_and_rewrite(job->options.at(5)))
	{
		/* Firstly, replace 'linker' with one that can track when new inputs
		 * are added.
		 * GAH. This is like method overriding but we have to do it a hand-rolled
		 * way.
		 * FIXME: macroise this whole thing:
		 * OVERRIDE_FP_WITH_MEMBFUN() for the class-level decls and
		 * OVERRIDE_FP_WITH_MEMBFUN_INIT() for the constructor stuff. */
		struct input_tracking_linker : linker_s
		{
			static vector<unsigned char> read64(const char *pathname)
			{
				FILE *f = fopen(pathname, "r");
				if (!f) return vector<unsigned char>();
				unsigned char bytes[64];
				vector<unsigned char> bvec;
				ssize_t nread = fread(&bytes[0], 1, 64, f);
				std::copy(bytes, bytes + nread, std::back_inserter(bvec));
				fclose(f);
				return bvec;
			}
			struct link_job *job;
			enum ld_plugin_status (*orig_add_input_file) (const char *pathname);
			enum ld_plugin_status add_input_file_memb(const char *pathname)
			{
				job->input_files.insert(make_pair(
					make_pair(pathname, 0),
					make_pair(1, read64(pathname))
				));
				return orig_add_input_file(pathname);
			}
			typedef srk31::ffi_closure_s< input_tracking_linker, enum ld_plugin_status, const char * >
				add_input_file_closure_s;
			std::unique_ptr< enum ld_plugin_status(const char *) ,
				add_input_file_closure_s::closure_deleter > add_input_file_closure_up;
			/* 'upgrade' constructor */
			input_tracking_linker(std::unique_ptr<struct linker_s> orig_linker,
				struct link_job *job) : job(job)
			{
				// copy the 'vtable'
				// FIXME: use std::swap?
				memcpy(static_cast<struct linker_s *>(this),
					orig_linker.get(), sizeof (struct linker_s));
				// remember the orig 'method'
				this->orig_add_input_file = this->add_input_file;
				// keep a unique pointer
				this->add_input_file_closure_up
				 = add_input_file_closure_s::make_closure<
				      &input_tracking_linker::add_input_file_memb
				   >(this);
				// also keep a raw pointer
				this->add_input_file = add_input_file_closure_up.get();

				// END: orig linker will now get deleted
			}
		};
		/* upgrade our linker interface object to one that
		 * remembers the inputs being added using add_input_file. */
		this->linker = std::make_unique<input_tracking_linker>(std::move(this->linker), this->job.get());
		/* extract the relevant symbol names from our environment variables */
		set<string> idents;
		for (unsigned n = 0 /* alloc_fns */; n <= 4 /* subfree_fns */; ++n)
		{
			set<string> extracted = extract_idents(job->options.at(n));
			std::copy(extracted.begin(), extracted.end(), std::inserter(idents, idents.begin()));
		}
		/* If we find a symname containing '::' we will treat it as a
		 * local symname. Ideally the '::' expr would be parsed as dwarfidl,
		 * but for now just take it as <.o filename>::<local_sym>
		 * and remember it in a separate list. We will look for these
		 * .o files in our claim-file handler, globalize and rename/mangle the
		 * symbol (no point making an alias -- it's local),
		 * and use this globalized+mangled symname as what we feed forward
		 * to xwrap.
		 *
		 * THEN we need the xwrap plugin, xwrapping all the symbols
		 * mentioned in the _fns options. Restart if we don't have it.
		 *
		 * Somewhere we need to scrape whether 'malloc' is defined, and tweak
		 * the allocstubs cppflags accordingly.
		 *
		 * Then we're ready to generate out allocstubs and usedtypes objects.
		 * and add them to the link; do this in all_symbols_read.
		 */
		auto missing_emit_relocs = [](vector<string> const& cmdline_vec)
		 -> pair<bool, vector<string> > 
		{
			if (std::find(cmdline_vec.begin(), cmdline_vec.end(), string("-q")) == cmdline_vec.end()
				&& std::find(cmdline_vec.begin(), cmdline_vec.end(), string("--emit-relocs")) == cmdline_vec.end())
			{
				auto new_vec = cmdline_vec;
				new_vec.push_back("--emit-relocs");
				return make_pair(true, new_vec);
			}
			return make_pair(false, cmdline_vec);
		};
		RESTART_IF(no_emit_relocs, missing_emit_relocs, job->cmdline);
			debug_println(0, "-q or --emit-relocs was%s initially set",
			no_emit_relocs.did_restart ? " not" : "");

		/* Now populate local_syms_to_globalize_by_filename.
		 * We need to intersect what we've been asked for
		 * with what's present in the link.
		 *
		 * Which local symbols might we need to globalize?
		 * Iterate over the inputs and if any has a local symbol
		 * matching one of our to-wrap symnames, rename it to something
		 * unique and globalize it.
		 */
		auto input_files = enumerate_input_files(job->cmdline);
		for (auto i_file = input_files.begin(); i_file != input_files.end(); ++i_file)
		{
			debug_println(0, "Input file: %s", i_file->c_str());
		}
		// populate global_symnames_of_interest and
		// file_and_local_symname_pairs_of_interest!
		for (auto i_ident = idents.begin(); i_ident != idents.end(); ++i_ident)
		{
			/* does it contain '::'? */
			smatch m;
			if (std::regex_match(*i_ident, m, std::regex("(.*)::(.*)")))
			{
				file_and_local_symname_pairs_of_interest.insert(make_pair(m[0], m[1]));
			}
			else global_symnames_of_interest.insert(*i_ident);
		}
		// FIXME: factor out a shorter 'collect_symbols_matching' from below?
		file_and_local_symname_pairs_to_globalize = classify_input_objects< set<string> >(
			input_files,
			[this](fmap const& f, off_t offset, string const& fname) -> set<string> {
				set<pair< ElfW(Sym)*, string > > pairs = enumerate_symbols_matching(f, offset,
					[this, &f, fname](ElfW(Sym)* sym, string const& name) -> bool {
						return (ELFW_ST_TYPE(sym->st_info) == STT_OBJECT
							  ||  ELFW_ST_TYPE(sym->st_info) == STT_FUNC)
							  && (sym->st_shndx != SHN_UNDEF && sym->st_shndx != SHN_ABS)
							  && (ELFW_ST_BIND(sym->st_info) == STB_LOCAL)
							  && (std::find(
							  	file_and_local_symname_pairs_of_interest.begin(),
								file_and_local_symname_pairs_of_interest.end(),
								make_pair( fname, name )) !=
								 file_and_local_symname_pairs_of_interest.end());
					}
				);
				set<string> ret; for (auto pair : pairs) ret.insert(pair.second);
				return ret;
			}
		);
		// global symbols -- similar weeding needed
		global_symnames_to_xwrap_by_input_file = classify_input_objects< set<string> >(
			input_files,
			[this](fmap const& f, off_t offset, string const& fname) -> set<string> {
				set<pair< ElfW(Sym)*, string > > pairs = enumerate_symbols_matching(f, offset,
					[this, &f, fname](ElfW(Sym)* sym, string const& name) -> bool {
						return (ELFW_ST_TYPE(sym->st_info) == STT_OBJECT
							  ||  ELFW_ST_TYPE(sym->st_info) == STT_FUNC)
							  && (sym->st_shndx != SHN_UNDEF && sym->st_shndx != SHN_ABS)
							  && (ELFW_ST_BIND(sym->st_info) != STB_LOCAL)
							  && (std::find(
							  	global_symnames_of_interest.begin(),
								global_symnames_of_interest.end(),
								name) != global_symnames_of_interest.end());
					}
				);
				set<string> ret;
				for (auto pair : pairs)
				{
					ret.insert(pair.second);
					// HACK: also add to the flat set
					global_symnames_to_xwrap.insert(pair.second);
				}
				return ret;
			}
		);
		
		// FIXME: generalise this
		/* auto files_defining_malloc = */ classify_input_objects< set<pair< ElfW(Sym)*, string > > >(
			input_files,
			[this](fmap const& f, off_t offset, string const& fname) {
				if (dynamic_cast<elfmap const *>(&f) && dynamic_cast<elfmap const &>(f).hdr->e_type == ET_REL)
					return enumerate_symbols_matching(f, offset,
					[this, &f, fname](ElfW(Sym)* sym, string const& name) -> bool {
						bool saw_it = (ELFW_ST_TYPE(sym->st_info) == STT_OBJECT
							  ||  ELFW_ST_TYPE(sym->st_info) == STT_FUNC)
							  && (sym->st_shndx != SHN_UNDEF && sym->st_shndx != SHN_ABS)
							  && (ELFW_ST_BIND(sym->st_info) != STB_LOCAL)
							  && (name == "malloc");
						if (saw_it) saw_malloc = std::optional<string>(string(fname));
						return saw_it;
					}
				);
				else return set< pair<ElfW(Sym)*, string> >();
			}
		);

		// now in claim_file_handler we can globalize as appropriate
		// .. but we need the xwrapping
		auto missing_xwrap_options = /* a function that looks for --wrap options and adds any missing */
			[this](vector<string> const& cmdline_vec) -> pair<bool, vector<string> > {
			set<string> cmdline_xwrapped_syms;
			int xwrap_plugin_idx = -1;
			int later_plugin_idx = -1;
			/* Where is the xwrap ldplugin? One way to do it is
			 * to look for it in the same directory as we are.
			 * Or use an environment variable. */
			const char *xwrap_ldplugin_envvar = getenv("XWRAP_LDPLUGIN");
			string xwrap_ldplugin_path;
			if (xwrap_ldplugin_envvar) xwrap_ldplugin_path = xwrap_ldplugin_envvar;
			else
			{
				struct link_map *us;
			here:
				us = get_link_map(&&here); // FIXME: avoid this gnuism
				assert(us);
				// dirname modifies its argument, so use C-style strings...
				char *working = strdup(us->l_name);
				char *dir = dirname(working);
				// FIXME: ... but instead should just use boost::filesystem as we do anyway
				boost::filesystem::path expected_ldplugin = boost::filesystem::path(dir) /
					"xwrap-ldplugin.so";
				xwrap_ldplugin_path = expected_ldplugin.c_str();
				free(working);
			}
			auto is_xwrap_plugin = [&xwrap_ldplugin_path](const string& arg) -> bool {
				return 0 == strcmp(::basename((char*) arg.c_str()), ::basename((char*) xwrap_ldplugin_path.c_str()));
			};
			// FIXME: factor out utility code for probing other plugins
			// ... really want some way for plugins to identify each other robustly.
			// This idea of multiple plugins working together, plugins invoking other
			// plugins etc, is not foreseen in the plugin API design. Maybe that's a
			// sign it's not a sane thing to do, and we should instead e.g. link in
			// the other-plugin code as a static library? That makes the compositionality
			// of what we're doing less evident, so less comprehensible/debuggable, because
			// it would then not unfold by a sequence of command-line rewrites, as it
			// currently does. The rewrite (restart) thing is a big hack, though. Hmm.
			// We need the rewrite mechanism because we need to add --wrap. We're going
			// on to make over-full use of it, arguably.
			for (auto i_str = cmdline_vec.begin(); i_str != cmdline_vec.end(); ++i_str)
			{
				int cur_idx = i_str - cmdline_vec.begin();
				// wart: "-plugin" is a prefix of "-plugin-opt", so take care
				if (!STARTS_WITH(*i_str, "-plugin-opt") && STARTS_WITH(*i_str, "-plugin"))
				{
					string arg = GETARG(i_str, "-plugin");
					debug_println(0, "Saw an arg `%s'", arg.c_str());
					if (is_xwrap_plugin(arg))
					{
						debug_println(0, "Saw the xwrap plugin `%s'", arg.c_str());
						xwrap_plugin_idx = cur_idx;
					}
					else if (xwrap_plugin_idx != -1 && later_plugin_idx == -1)
					{ later_plugin_idx = cur_idx; }
					continue;
				}
				if (STARTS_WITH(*i_str, "-plugin-opt") &&
					xwrap_plugin_idx != -1 && cur_idx >= xwrap_plugin_idx &&
					(later_plugin_idx == -1 || cur_idx < later_plugin_idx))
				{
					string arg = GETARG(i_str, "-plugin-opt");
					debug_println(0, "We think `%s' is an argument to the xwrap plugin", arg.c_str());
					cmdline_xwrapped_syms.insert(arg);
				}
			}
			// are there any wraps needed that we don't have?
			set<string> missing;
			for (string needed : global_symnames_to_xwrap)
			{
				if (cmdline_xwrapped_syms.find(needed) == cmdline_xwrapped_syms.end())
				{
					// not found
					missing.insert(needed);
				}
			}
			if (xwrap_plugin_idx == -1 || missing.size() > 0)
			{
				vector<string> new_vec = cmdline_vec;
				if (xwrap_plugin_idx == -1)
				{
					xwrap_plugin_idx = new_vec.size();
					new_vec.push_back(string("-plugin=") + xwrap_ldplugin_path);
					debug_println(0, "Added missing xwrap plugin at `%s'", xwrap_ldplugin_path.c_str());
				}
				if (missing.size() > 0)
				{
					auto pos = new_vec.begin() + xwrap_plugin_idx + 1;
					for (auto& one_missing : missing)
					{
						new_vec.insert(pos, string("-plugin-opt=") + one_missing);
						debug_println(0, "Added missing xwrap option for `%s'", one_missing.c_str());
					}
					return make_pair(true, new_vec);
				}
			}
			return make_pair(false, cmdline_vec);
		};
		RESTART_IF(missing_any_xwrap_options, missing_xwrap_options, job->cmdline);
		debug_println(0, "all needed xwrap options were%s initially set",
			missing_any_xwrap_options.did_restart ? " not" : "");

		auto missing_liballocs_rpath =
			[this](vector<string> const& cmdline_vec) -> pair<bool, vector<string> > {
			vector<string> current_rpath;
			for (auto i_str = cmdline_vec.begin(); i_str != cmdline_vec.end(); ++i_str)
			{
				string arg;
				if (STARTS_WITH(*i_str, "-rpath") && i_str + 1 != cmdline_vec.end())
				{
					arg = *(i_str+1);
				}
				else if (STARTS_WITH(*i_str, "-R"))
				{
					arg = GETARG(i_str, "-R");
					// skip non-directories, as -R means something else then
					if (!boost::filesystem::is_directory(boost::filesystem::path(arg))) continue;
				}
				current_rpath.push_back(arg);
			}
			/* Does it include liballocs's dir? If LIBALLOCS is not set,
			 * we can't do anything. */
			const char *liballocs_env = getenv("LIBALLOCS");
			auto realpath_match = [](const string& p1, const string& p2) -> bool {
				char *realpath1 = realpath(p1.c_str(), NULL);
				char *realpath2 = realpath(p2.c_str(), NULL);
				bool ret = (realpath1 && realpath2 && 0 == strcmp(realpath1, realpath2));
				free(realpath1);
				free(realpath2);
				return ret;
			};
			if (!liballocs_env
				|| current_rpath.end() != std::find_if(
					current_rpath.begin(), current_rpath.end(),
					[realpath_match, liballocs_env](const string& s)
					{ return realpath_match((boost::filesystem::path(liballocs_env) / "lib").c_str(),
						s); }
					))
			{
				return make_pair(false, cmdline_vec);
			}
			vector<string> new_vec = cmdline_vec;
			new_vec.push_back("-rpath");
			new_vec.push_back((boost::filesystem::path(liballocs_env) / "lib").c_str());
			return make_pair(true, new_vec);
			
		};
		/* Only use this one if we're not outputting a REL object,
		 * since if that's true we won't try to add liballocs to the link. */
		if (job->output_file_type != LDPO_REL)
		{
			RESTART_IF(missing_liballocs_rpath_option, missing_liballocs_rpath, job->cmdline);
			debug_println(0, "liballocs rpath was%s initially set",
				missing_liballocs_rpath_option.did_restart ? " not" : "");
		}

		auto missing_allocsld =
			[this](vector<string> const& cmdline_vec) -> pair<bool, vector<string> > {
			std::optional<string> current_dynamic_linker;
			vector<string>::const_iterator current_dynamic_linker_pos = cmdline_vec.end();
			for (auto i_str = cmdline_vec.begin(); i_str != cmdline_vec.end(); ++i_str)
			{
				string arg;
				if ((STARTS_WITH(*i_str, "--dynamic-linker") || STARTS_WITH(*i_str, "-dynamic-linker"))
				 && i_str + 1 != cmdline_vec.end())
				{
					arg = *(i_str+1);
				}
				else if (STARTS_WITH(*i_str, "-I"))
				{
					arg = GETARG(i_str, "-I");
				}
				else continue;
				// now we definitely have 'arg'
				assert(arg != "");
				if (!!current_dynamic_linker)
				{
					linker->message(LDPL_WARNING, "dynamic linker specified multiple times");
				}
				current_dynamic_linker = arg;
				current_dynamic_linker_pos = i_str;
			}
			/* Does it include allocsld? If LIBALLOCS is not set,
			 * we can't do anything. */
			const char *liballocs_env = getenv("LIBALLOCS");
			auto realpath_match = [](const string& p1, const string& p2) -> bool {
				char *realpath1 = realpath(p1.c_str(), NULL);
				char *realpath2 = realpath(p2.c_str(), NULL);
				bool ret = (realpath1 && realpath2 && 0 == strcmp(realpath1, realpath2));
				free(realpath1);
				free(realpath2);
				return ret;
			};
			if (!liballocs_env) linker->message(LDPL_WARNING, "can't set dynamic linker to allocsld; no LIBALLOCS");
			if (!liballocs_env
				|| (!!current_dynamic_linker && realpath_match(
					     (boost::filesystem::path(liballocs_env) / "lib/allocsld.so").c_str(),
					     *current_dynamic_linker
					  )
					)
				)
			{
				// --dynamic-linker is already passed, specifying allocsld -- no need to change anything
				return make_pair(false, cmdline_vec);
			}
			if (!!current_dynamic_linker
				&& current_dynamic_linker != job->system_dynamic_linker())
			{
				linker->message(LDPL_WARNING, "not setting dynamic linker to allocsld; "
					"already set to another non-standard one (`%s')",
					current_dynamic_linker->c_str());
				return make_pair(false, cmdline_vec);
			}
			string allocsld_path = (boost::filesystem::path(liballocs_env) / "lib/allocsld.so").c_str();
			assert(allocsld_path != "");
			vector<string> new_vec = cmdline_vec;
			if (!!current_dynamic_linker)
			{
				new_vec[current_dynamic_linker_pos - cmdline_vec.begin() + 1] = allocsld_path;
			}
			else
			{
				new_vec.push_back("--dynamic-linker");
				new_vec.push_back(allocsld_path);
			}
			return make_pair(true, new_vec);
			
		};
		/* Only use this one if we're not outputting a REL object,
		 * since if that's true we won't try to add liballocs to the link. */
		if (job->output_file_type == LDPO_PIE || job->output_file_type == LDPO_EXEC)
		{
			RESTART_IF(missing_allocsld_option, missing_allocsld, job->cmdline);
			debug_println(0, "allocsld was%s initially {set or unsettable}",
				missing_allocsld_option.did_restart ? " not" : "");
		}
		/* If we're doing a 'final' (non-relocatable) link, we post-build
		 * the metadata for the output binary. And if we added -q, we strip
		 * the reloc info.
		 * FIXME: what's the right place for doing the corresponding strip
		 * of the debugging information, if we added -g? Since allocs-cflags
		 * added it, it somehow needs to request the stripping. From allocs-cflags:
		# We probably have to do something like add a .note section to the .s
		# if stripping is needed later. This basically means 'these .debug_*
		# sections are not really here and won't survive the link'.
		 */

	}
};
LINKER_PLUGIN(allocs_plugin);
#define define_regex(name, contents) \
    string allocs_plugin::name ## _re_s; \
    std::regex allocs_plugin::name ## _re;
regexes(define_regex)

/* This is for higher-order macro idiom where lists look like
 *     w(things1,blah,x) w(things2,bleh,y) w(things3,zap,z)
 * ... we split the string 's' into words and wrap each in a
 * dummy macro invocation, by default calling the macro 'w'.
 * For now, a 'word' is any match of the one_entry regex. */
string allocs_plugin::wordify(const string& s, char macro_name /* = 'w' */)
{
	return std::regex_replace(s, std::regex("(" + one_entry_re_s + ")"),
		string(1, macro_name) + "($1)");
}

/* if "malloc" in definedMatches, we will want to define LIBALLOCS_MALLOC_CALLEE_WRAPPERS
   ALLOC_EVENT_INDEXING_DEFS(__global_malloc, __global_malloc_usable_size)
   which generates the indexing event hook defs and a 'struct allocator',
   but not the malloc hooks on which the indexing events depend. So the
   following is a bespoke 'client' of the raw libmallochooks code
   (bypassing its usual rules.mk) which adds this hook logic.
   The hook entry points we generate here are called __wrap___real_* -- see below. */


/* Can we use higher-order macro programming to
 * save us from writeArgList?
 * It is taking strings like 'pZ' and generating 'make_arg(0, p)', 'make_arg(1, z)' etc.
 *
 * If I'm prepared to change the syntax here, e.g. to insert
 * commas, I could do a lot better,
 * maybe even generating it all from the preprocessor.
 *
 * e.g. instead of
 * LIBALLOCS_ALLOC_FNS="xcalloc(zZ)p xmalloc(Z)p"
 * if we had
 * -DLIBALLOCS_ALLOC_FNS(v) v(xcallocv(z,Z),p) v(xmallocv(Z),p)
 *
 * ... wouldn't that be enough? I think so.
 * BUT THERE'S MORE.
 * In our softbound emulation we use the 'rev_arglist' stuff for the shadow stack.
 * WHERE was this? Maybe not even just in SoftBound but also in main crunchbcc?
 * AHA. YES. include/stubgen_softbound.h
 * using the pre_ and do_ macro hooks
 * Does this change the above? No because it's still generated from macros.
 
 * Maybe the right way is to cppify it right now,
 * s.t. it's a trivial adjustment from what we have but in cpp-space
 * not env-space, i.e.
 * clients don't write 'export LIBALLOCS_ALLOC_FNS="Perl_safesysmalloc(Z)p'
 * but rather something like this:
 * perl: CFLAGS += -DALLOC_FNS='v(Perl_safesysmalloc(Z),p)'
 * ?
 * AH but that's a problem because this CFLAGS will get discarded;
 * it's needed for code generation at link time, where the makefile
 * doesn't even know that CFLAGS is needed.
 *
 * Maybe the allocs-ldflags wrapper should take LIBALLOCS_ALLOC_FNS and
 * turn it into an argument list for the actual plugin?
 * Basically there is a fixed argument tuple for the "allocator mods" content:
 * 
 * LIBALLOCS_ALLOC_FNS       \ just caller-side wrappers
 * LIBALLOCS_FREE_FNS        /
 * LIBALLOCS_ALLOCSZ_FNS     -- should go away with interprocedural?
 * LIBALLOCS_SUBALLOC_FNS    \ ... need overhaul of some kind
 * LIBALLOCS_SUBFREE_FNS     /
 * LIBALLOCS_ALLOCSITE_OVERRIDE
 *
 * whereas LIBALLOCS_ALLOCSITE_OVERRIDE is really for the runtime not the toolchain.
 * (but it could be baked into the binary, say as a custom DT_*, to be picked up
 * at init time, so leaving it here for now).
 * So let's make the 'options' for our linker plugin these six strings!
 *
 * Currently, Python code processes the signature lists into definitions of
 * the following five helpers, in whose terms the make_wrapper_* are defined.
 
   arglist_*(make_arg)              comma-sep'd arglist 
   rev_arglist_*(make_arg)
   arglist_nocomma_*(make_arg)
   rev_arglist_nocomma_*(make_arg)
   size_arg_*(make_arg)
 
 * Could I instead write generic ones?

   arglist(funspec, make_arg)              generate comma-sep'd arglist; make_arg takes (num, argchar)
   rev_arglist(funspec, make_arg)
   arglist_nocomma(funspec, make_arg)
   rev_arglist_nocomma(funspec, make_arg)
   size_arg(funspec, make_arg)

 * The inputs look like this.

LIBALLOCS_ALLOC_FNS="Perl_safesysmalloc(Z)p \
LIBALLOCS_FREE_FNS="Safefree(P) perl_free(P) PerlMem_free(P)"
LIBALLOCS_ALLOCSZ_FNS="__ckd_calloc_2d__(iiIpi)p __ckd_calloc_3d__(iiiIpi)p fe_create_2d(iiI)p"
LIBALLOCS_SUBALLOC_FNS="Perl_newSV(p)p"
LIBALLOCS_SUBFREE_FNS="libcrunch_free_object(P)->ggc_alloc"

 */

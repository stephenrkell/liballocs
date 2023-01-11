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
 * This is a bit nasty. We use a toolsub-esque wrapper to add one
 * plugin, then it adds more (+ more options, like --wrap).
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
	bool saw_malloc; // do we define 'malloc'?
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
		int ret = system((string("${META_CC:-cc} ") + insert + "-std=c11" + " ${META_CFLAGS:-${LIBALLOCSTOOL:+-I${LIBALLOCSTOOL}/include}} -fPIC -c -x c " + (quote_src_tmpfilename ? "'" : "") + src_tmpfilename + (quote_src_tmpfilename ? "'" : "") + " -o '" + obj_tmpfile.first + "'").c_str());
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
			debug_println(0, "%s %u %d %d %02x", pair.first.first.c_str(), pair.first.second,
				pair.second.first, bytes.size(),
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
			linker->message(LDPL_ERROR, "options must match regex `%s'",
				whole_var_re_s.c_str());
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
				return enumerate_symbols_matching(f, offset,
					[this, &f, fname](ElfW(Sym)* sym, string const& name) -> bool {
						bool saw_it = (ELFW_ST_TYPE(sym->st_info) == STT_OBJECT
							  ||  ELFW_ST_TYPE(sym->st_info) == STT_FUNC)
							  && (sym->st_shndx != SHN_UNDEF && sym->st_shndx != SHN_ABS)
							  && (ELFW_ST_BIND(sym->st_info) != STB_LOCAL)
							  && (name == "malloc");
						saw_malloc |= saw_it;
						return saw_it;
					}
				);
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
			string current_dynamic_linker = "";
			vector<string>::const_iterator current_dynamic_linker_pos;
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
				if (current_dynamic_linker != "")
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
				|| (current_dynamic_linker != "" && realpath_match(
					 (boost::filesystem::path(liballocs_env) / "lib/allocsld.so").c_str(),
					 current_dynamic_linker)
					)
				)
			{
				return make_pair(false, cmdline_vec);
			}
			if (current_dynamic_linker != ""
				&& std::optional<string>(current_dynamic_linker) != job->system_dynamic_linker())
			{
				linker->message(LDPL_WARNING, "not setting dynamic linker to allocsld; "
					"already set to another non-standard one (`%s')",
					current_dynamic_linker.c_str());
				return make_pair(false, cmdline_vec);
			}
			string allocsld_path = (boost::filesystem::path(liballocs_env) / "lib/allocsld.so").c_str();
			vector<string> new_vec = cmdline_vec;
			if (current_dynamic_linker != "")
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

 * YES if we change the syntax slightly by inserting more commas.
 * So let's do that.
 * - rewrite so that each word gets wrapped in v( ... )
 * - rewrite so that '(' becomes  ',(' and ')' to '),' (for some vars only?)
 * - rewrite so that within '()', commas are inserted between characters
 * - rewrite so that '->' becomes ',' (for LIBALLOCS_SUBFREE_FNS only)


# this does most of it but not the commas within the parens
  for v in $LIBALLOCS_VAR; do
      IFS=$'\t' read ident args after <<<"$( echo "$v" | tr '()' '\t' )"
      echo "${ident},($(echo "$args" | sed 's/./&,/g' | sed 's/,$//'))$(echo "$after" | sed 's/->//' | sed 's/.+/,&/')"

  done

      echo "${ident},($(echo "$args" | sed 's/./&,/g')"),$(echo "$after" | sed 's/->//' | sed 's/.+/,&/')"
  done
  sed 's/(/,(/g' | \
  sed -E 's/\)([a-zA-Z].*)/\),\1/' | \
  sed 's/->/,/' 


 * Can I reverse a list from the preprocessor? yes
 
 */
#if 0

/* For the type arg below, why do we need
 * to know *here* the size of the allocated thing?
 * What happens if the size arg is just not defined?
 * Then we can't set __current_allocsz.
 * That matters if we are using LIBALLOCS_ALLOCSZ_FUN
 * It looks like the only other place where we need it is a call to
 * __index_small_alloc.
 * Indeed it's gcc and perlbench that use this no-size-arg facility.
 *
crunchrc-gcc:export LIBALLOCS_ALLOCSZ_FNS="tree_size(p)Z" # -- won't work as is
scripts/harness/crunchrc-perlbench:#export LIBALLOCS_SUBALLOC_FNS="Perl_newSV(p)p \
	S_new_he(p)p \
	S_new_xiv(p)p \
	S_new_xnv(p)p \
	S_new_xrv(p)p \
	S_new_xpv(p)p \
	S_new_xpviv(p)p \
	S_new_xpvnv(p)p \
	S_new_xpvcv(p)p \
	S_new_xpvav(p)p \
	S_new_xpvhv(p)p \
	S_new_xpvmg(p)p \
	S_new_xpvlv(p)p \
	S_new_xpvbm(p)p"

 * What's the right way to deal with this?
 * We could look up the size at run time using dlsym, and cache it locally.
 * We will need to expand the name of the allocated type, though. Do we have it?
 * Sort of... only in the linked-in debugging information. So need to replicate
 * find-allocated-type-size logic here, and pass the name to the macro. I guess
 * we should always look up the wrapped callee and its debug info... may help
 * us with a more dwarfidly approach one day.
 *
 * Maybe we need a size_expr, that is defined either as 'argN' or as
 * lookup_and_cache_return_pointee_type_size(the_fn) ?
 */


                # generate caller-side alloc stubs
                for allocFn in self.allAllocFns():
                    m = re.match("(.*)\((.*)\)(.?)", allocFn)
                    fnName = m.groups()[0]
                    fnSig = m.groups()[1]
                    retSig = m.groups()[2]
                    writeArgList(fnName, fnSig)
                    sizendx = self.findFirstUpperCase(fnSig)
                    if sizendx != -1:
                        # it's a size char, so flag that up
                        stubsfile.write("#define size_arg_%s make_argname(%d, %c)\n" % (fnName, sizendx, fnSig[sizendx]))
                    else:
                        # If there's no size arg, it's a typed allocation primitive, and 
                        # the size is the size of the thing it returns. How can we get
                        # at that? Have we built the typeobj already? No, because we haven't
                        # even built the binary. But we have built the .o, including the
                        # one containing the "real" allocator function. Call a helper
                        # to do this.
                        size_find_command = [self.getLibAllocsBaseDir() \
                            + "/tools/find-allocated-type-size", fnName] + [ \
                            objfile for objfile in passedThroughArgs if objfile.endswith(".o")]
                        self.debugMsg("Calling " + " ".join(size_find_command) + "\n")
                        outp = subprocess.Popen(size_find_command, stdout=subprocess.PIPE).communicate()[0].decode()
                        self.debugMsg("Got output: " + outp + "\n")
                        # we get lines of the form <number> \t <explanation>
                        # so just chomp the first number
                        outp_lines = outp.split("\n")
                        if (len(outp_lines) < 1 or outp_lines[0] == ""):
                            self.debugMsg("No output from %s" % " ".join(size_find_command))
                            return 1  # give up now
                        sz = int(outp_lines[0].split("\t")[0])
                        stubsfile.write("#define size_arg_%s %d\n" % (fnName, sz))
                    if allocFn in self.allL1OrWrapperAllocFns():
                        stubsfile.write("make_caller_wrapper(%s, %s)\n" % (fnName, retSig))
                    elif allocFn in self.allAllocSzFns():
                        stubsfile.write("make_size_caller_wrapper(%s, %s)\n" % (fnName, retSig))
                    else:
                        stubsfile.write("make_suballocator_alloc_caller_wrapper(%s, %s)\n" % (fnName, retSig))
                    # for genuine allocators (not wrapper fns), also make a callee wrapper
                    if allocFn in self.allSubAllocFns(): # FIXME: cover non-sub clases
                        stubsfile.write("make_callee_wrapper(%s, %s)\n" % (fnName, retSig))
                    stubsfile.flush()
                # also do caller-side subfree wrappers
                for freeFn in self.allSubFreeFns():
                    m = re.match("(.*)\((.*)\)(->([a-zA-Z0-9_]+))", freeFn)
                    fnName = m.groups()[0]
                    fnSig = m.groups()[1]
                    allocFnName = m.groups()[3]
                    ptrndx = fnSig.find('P')
                    if ptrndx != -1:
                        # it's a ptr, so flag that up
                        stubsfile.write("#define ptr_arg_%s make_argname(%d, %c)\n" % (fnName, ptrndx, fnSig[ptrndx]))
                    writeArgList(fnName, fnSig)
                    stubsfile.write("make_suballocator_free_caller_wrapper(%s, %s)\n" % (fnName, allocFnName))
                    stubsfile.flush()
                    if allocFn in self.allSubFreeFns(): # FIXME: cover non-sub and non-void clases
                        stubsfile.write("make_void_callee_wrapper(%s)\n" % (fnName))
                # also do caller-side free (non-sub) -wrappers
                for freeFn in self.allL1OrWrapperFreeFns():
                    m = re.match("(.*)\((.*)\)", freeFn)
                    fnName = m.groups()[0]
                    fnSig = m.groups()[1]
                    ptrndx = fnSig.find('P')
                    if ptrndx != -1:
                        # it's a ptr, so flag that up
                        stubsfile.write("#define ptr_arg_%s make_argname(%d, %c)\n" % (fnName, ptrndx, fnSig[ptrndx]))
                    writeArgList(fnName, fnSig)
                    stubsfile.write("make_free_caller_wrapper(%s)\n" % fnName)
                    stubsfile.flush()
                if "malloc" in definedMatches:
                    stubsfile.write('#include "generic_malloc_index.h"\n')
                    stubsfile.write('\nALLOC_EVENT_INDEXING_DEFS(__global_malloc, malloc_usable_size)\n')
                    stubsfile.flush()
                    (dynamicListFd, dynamicListFilename) = tempfile.mkstemp()
                    os.unlink(dynamicListFilename)
                    os.write(dynamicListFd, b"{\n")
                    for sym in definedMatches:
                        # FIXME: only do this if the original sym was export-dynamic'd,
                        # and only for malloc-family syms
                        # HMM. Older linkers don't support --export-dynamic-symbol,
                        # so we may have to fall back on --dynamic-list.
                        # stubsLinkArgs += [ "-Wl,--export-dynamic-symbol," + "__real_" + sym]
                        os.write(dynamicListFd, bytes(sym, 'utf-8') + b";\n")
                    # GAH. If we use NamedTemporaryFile it gets collected too soon.
                    # HACK: use /proc/self/fd/NN
                    stubsLinkArgs += ["-Wl,--dynamic-list," + ("/proc/%d/fd/%d" % (os.getpid(), dynamicListFd))]
                    os.write(dynamicListFd, b"};\n")
                # now we compile the C file ourselves, rather than cilly doing it, 
                # because it's a special magic stub
                stubs_pp = os.path.splitext(stubsfile.name)[0] + ".i"
                stubs_bin = os.path.splitext(stubsfile.name)[0] + ".o"
                # We *should* pass through some options here, like -DNO_TLS. 
                # To do "mostly the right thing", we preprocess with 
                # most of the user's options, 
                # then compile with a more tightly controlled set
                extraFlags = self.getStubGenCompileArgs()
                extraFlags += ["-fPIC"]
                # WHERE do we get relf.h, in the librunt era?
                # Bit of a hack: in the contrib. FIXME FIXME.
                stubs_pp_cmd = self.getBasicCCompilerCommand() + ["-std=c11", "-E", "-Wp,-dD", "-Wp,-P"] \
                    + extraFlags + ["-o", stubs_pp, \
                    "-I" + self.getLibAllocsBaseDir() + "/tools", \
                    "-I" + self.getLibAllocsBaseDir() + "/include", \
                    ] \
                    + [arg for arg in self.phaseItems[Phase.PREPROCESS] if arg.startswith("-D")] \
                    + [stubsfile.name] #, "-Wp,-P"]
                self.debugMsg("Preprocessing stubs file %s to %s with command %s\n" \
                    % (stubsfile.name, stubs_pp, " ".join(stubs_pp_cmd)))
                ret_stubs_pp = subprocess.call(stubs_pp_cmd)
                if ret_stubs_pp != 0:
                    self.debugMsg("Could not preproces stubs file %s: compiler returned %d\n" \
                        % (stubsfile.name, ret_stubs_pp))
                    exit(1)
                # now erase the '# ... file ' lines that refer to our stubs file,
                # and add some line breaks
                # -- HMM, why not just erase all #line directives? i.e. preprocess with -P?
                # We already do this.
                # NOTE: the "right" thing to do is keep the line directives
                # and replace the ones pointing to stubgen.h
                # with ones pointing at the .i file itself, at the appropriate line numbers.
                # This is tricky because our insertion of newlines will mess with the
                # line numbers.
                # Though, actually, we should only need a single #line directive.
                # Of course this is only useful if the .i file is kept around.
                #stubs_sed_cmd = ["sed", "-r", "-i", "s^#.*allocs.*/stubgen\\.h\" *[0-9]* *$^^\n " \
                #+ "/__real_|__wrap_|__current_/ s^[;\\{\\}]^&\\n^g", stubs_pp]
                #ret_stubs_sed = subprocess.call(stubs_sed_cmd)
                # _if ret_stubs_sed != 0:
                #    self.debugMsg("Could not sed stubs file %s: sed returned %d\n" \
                #        % (stubs_pp, ret_stubs_sed))
                #    exit(1)
                stubs_cc_cmd = self.getBasicCCompilerCommand() + ["-std=c11", "-g"] + extraFlags + ["-c", "-o", stubs_bin, \
                    "-I" + self.getLibAllocsBaseDir() + "/tools", \
                    stubs_pp]
                self.debugMsg("Compiling stubs file %s to %s with command %s\n" \
                    % (stubs_pp, stubs_bin, " ".join(stubs_cc_cmd)))
                stubs_output = None
                try:
                    stubs_output = subprocess.check_output(stubs_cc_cmd, stderr=subprocess.STDOUT)
                except subprocess.CalledProcessError as e:
                    self.debugMsg("Could not compile stubs file %s: compiler returned %d and said %s\n" \
                        % (stubs_pp, e.returncode, str(e.output)))
                    exit(1) # exit the whole process?!
                if stubs_output != b'':
                    self.debugMsg("Compiling stubs file %s: compiler said \"%s\"\n" \
                        % (stubs_pp, stubs_output))
                return (stubs_bin, stubsLinkArgs)

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

static std::optional<string> stubs;
static std::optional<string> meta;

std::optional<string> generate_allocator_stubs_object()
{
	return std::optional<string>();
}

std::optional<string> generate_meta_object()
{
	return std::optional<string>();
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
#endif


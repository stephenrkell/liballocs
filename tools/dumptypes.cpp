/* This is a simple dwarfpp program which generates a C file
 * recording data on a uniqued set of data types  allocated in a given executable.
 */
 
#include <fstream>
#include <sstream>
#include <map>
#include <set>
#include <unordered_set>
#include <unordered_map>
#include <string>
#include <cctype>
#include <cstdlib>
#include <memory>
#include <boost/regex.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/icl/interval_map.hpp>
#include <srk31/algorithm.hpp>
#include <srk31/ordinal.hpp>
#include <cxxgen/tokens.hpp>
#include <dwarfpp/lib.hpp>
#include <dwarfpp/frame.hpp>
#include <dwarfpp/regs.hpp>
#include <fileno.hpp>

#include "helpers.hpp"
#include "uniqtypes.hpp"

#include <elf.h>
#include <link.h>
#include "libelf/gelf.h"

using std::cin;
using std::cout;
using std::cerr;
using std::map;
using std::make_shared;
using std::ios;
using std::ifstream;
using std::dynamic_pointer_cast;
using boost::optional;
using std::ostringstream;
using std::set;
using namespace dwarf;
//using boost::filesystem::path;
using dwarf::core::iterator_base;
using dwarf::core::iterator_df;
using dwarf::core::iterator_sibs;
using dwarf::core::type_die;
using dwarf::core::subprogram_die;
using dwarf::core::compile_unit_die;
using dwarf::core::member_die;
using dwarf::core::with_data_members_die;
using dwarf::core::variable_die;
using dwarf::core::program_element_die;
using dwarf::core::with_dynamic_location_die;
using dwarf::core::address_holding_type_die;
using dwarf::core::array_type_die;
using dwarf::core::type_chain_die;

using namespace dwarf::lib;

// regex usings
using boost::regex;
using boost::regex_match;
using boost::smatch;
using boost::regex_constants::egrep;
using boost::match_default;
using boost::format_all;

static string typename_for_vaddr_interval(iterator_df<subprogram_die> i_subp, 
	const boost::icl::discrete_interval<Dwarf_Off> interval);

static string typename_for_vaddr_interval(iterator_df<subprogram_die> i_subp, 
	const boost::icl::discrete_interval<Dwarf_Off> interval)
{
	std::ostringstream s_typename;
	if (i_subp.name_here()) s_typename << *i_subp.name_here();
	else s_typename << "0x" << std::hex << i_subp.offset_here() << std::dec;
	s_typename << "_vaddrs_0x" << std::hex << interval.lower() << "_0x" 
		<< interval.upper() << std::dec;

	return s_typename.str();
}

static int debug_out = 1;

using dwarf::lib::Dwarf_Off;
using dwarf::lib::Dwarf_Addr;
using dwarf::lib::Dwarf_Signed;
using dwarf::lib::Dwarf_Unsigned;

template <typename Second>
struct compare_first_iter_offset
{
	bool operator()(const pair< iterator_df<with_dynamic_location_die>, Second >& x,
		            const pair< iterator_df<with_dynamic_location_die>, Second >& y)
		const
	{
		return x.first.offset_here() < y.first.offset_here();
	}
};

struct compare_first_signed_second_offset
{
	bool operator()(const pair< Dwarf_Signed, iterator_df<with_dynamic_location_die> >& x,
		            const pair< Dwarf_Signed, iterator_df<with_dynamic_location_die> >& y)
		const
	{
		return (x.first < y.first)
			|| ((x.first == y.first) && x.second.offset_here() < y.second.offset_here());
	}
};

using std::unordered_set;

template <class Target>
struct iter_hash
{
	typedef iterator_df<Target> T;
	
	static size_t hash_fn(const T& v) { return v.offset_here(); }
	static bool eq_fn(const T& v1, const T& v2)
	{ return v1.offset_here() == v2.offset_here(); }
	
	struct set : unordered_set<
		T,
		std::function<__typeof__(hash_fn)>,
		std::function<__typeof__(eq_fn)>
	>
	{
		set() : unordered_set<T, std::function<__typeof__(hash_fn)>, std::function<__typeof__(eq_fn)> >({}, 0, hash_fn, eq_fn) {}
	};
};

template <class Target, class Second>
struct iterfirst_pair_hash
{
	typedef pair<iterator_df<Target>, Second> T;
	
	static size_t hash_fn(const T& v)
	{ return v.first.offset_here() ^ std::hash<Second>()(v.second); }
	static bool eq_fn(const T& v1,  const T& v2)
	{ return v1.first.offset_here() == v2.first.offset_here(); }

	struct set : unordered_set< 
		T,
		std::function<__typeof__(hash_fn)>,
		std::function<__typeof__(eq_fn)>
	>
	{
		set() : unordered_set<T, std::function<__typeof__(hash_fn)>, std::function<__typeof__(eq_fn)> >
			({}, 0, hash_fn, eq_fn) 
			{}
	};
};

template <class First, class Target>
struct itersecond_pair_hash
{
	typedef pair<First, iterator_df<Target> > T;
	
	static size_t hash_fn(const T& v) 
	{ return v.second.offset_here() ^ std::hash<First>()(v.first); }
	static bool eq_fn(const T& v1, 	const T& v2)
	{ return v1.first == v2.first &&
	    v1.second.offset_here() == v2.second.offset_here(); }

	struct set : unordered_set< 
		T,
		std::function<__typeof__(hash_fn)>,
		std::function<__typeof__(eq_fn)>
	>
	{
		set() : unordered_set<T, std::function<__typeof__(hash_fn)>, std::function<__typeof__(eq_fn)> >
			({}, 0, hash_fn, eq_fn) 
			{}
	};
};


namespace std {
template <>
struct hash<const dwarf::lib::Dwarf_Loc>
{
	size_t operator()(const dwarf::lib::Dwarf_Loc& v)
	{
		size_t working = 0;
		working ^= v.lr_atom;
		working ^= v.lr_number;
		working ^= v.lr_number2;
		working ^= v.lr_offset;
		return working;
	}
};
template <>
struct hash<dwarf::encap::loc_expr>
{
	size_t operator()(const dwarf::encap::loc_expr& v)
	{
		size_t working = 0;
		for (auto i = v.begin(); i != v.end(); ++i)
		{
			working ^= std::hash<__typeof__(*i)>()(*i);
		}
		return working;
	}
};
}

int main(int argc, char **argv)
{
	/* We open the file named by argv[1] and dump its DWARF types. */ 
	
	if (argc <= 1) 
	{
		cerr << "Please name an input file." << endl;
		exit(1);
	}
	std::ifstream infstream(argv[1]);
	if (!infstream) 
	{
		cerr << "Could not open file " << argv[1] << endl;
		exit(1);
	}
	
	if (getenv("DUMPTYPES_DEBUG"))
	{
		debug_out = atoi(getenv("DUMPTYPES_DEBUG"));
	}
	
	using core::root_die;
	int fd = fileno(infstream);
	struct sticky_root_die : public root_die
	{
		using root_die::root_die;
		
		virtual bool is_sticky(const core::abstract_die& d) 
		{
			return this->root_die::is_sticky(d)
				// || dwarf::spec::DEFAULT_DWARF_SPEC.tag_is_type(d.get_tag())
				;
		}
		
		// FIXME: support non-host-native size
	private:
		opt<ElfW(Sym) *> opt_symtab;
		char *strtab;
		unsigned n;
	public:
		pair<pair<ElfW(Sym) *, char*>, unsigned> get_symtab()
		{
			if (!opt_symtab)
			{
				Elf *e = get_elf();
				Elf_Scn *scn = NULL;
				GElf_Shdr shdr;
				size_t shstrndx;
				if (elf_getshdrstrndx(e, &shstrndx) != 0)
				{
					throw lib::No_entry();
				}
				// iterate through sections looking for symtab
				while (NULL != (scn = elf_nextscn(e, scn)))
				{
					if (gelf_getshdr(scn, &shdr) != &shdr)
					{
						cerr << "Unexpected ELF error" << std::endl;
						throw lib::No_entry(); 
					}
					if (shdr.sh_type == SHT_SYMTAB) break;
				}
				if (!scn) throw lib::No_entry();
				Elf_Data *symtab_rawdata = elf_rawdata(scn, NULL);
				assert(symtab_rawdata);
				assert(symtab_rawdata->d_size >= shdr.sh_size);
				ElfW(Sym) *symtab = reinterpret_cast<ElfW(Sym) *>(symtab_rawdata->d_buf);
				opt_symtab = symtab;
				n = shdr.sh_size / shdr.sh_entsize;
				int strtab_ndx = shdr.sh_link;
				if (strtab_ndx == 0) throw lib::No_entry();
				Elf_Scn *strtab_scn = NULL;
				strtab_scn = elf_getscn(e, strtab_ndx);
				GElf_Shdr strtab_shdr;
				if (gelf_getshdr(strtab_scn, &strtab_shdr) != &strtab_shdr) throw lib::No_entry();
				Elf_Data *strtab_rawdata = elf_rawdata(strtab_scn, NULL);
				assert(strtab_rawdata);
				assert(strtab_rawdata->d_size >= strtab_shdr.sh_size);
				strtab = reinterpret_cast<char *>(strtab_rawdata->d_buf);
				assert(strtab);
				assert(symtab);
				// FIXME: cleanup?
			}
			return make_pair(make_pair(*opt_symtab, strtab), n);
		}
		~sticky_root_die()
		{
			if (opt_symtab)
			{
				// anything to free?
			}
			
			// this->root_die::~root_die(); // uncomment this when ~root_die is virtual. OH. it is.
		}
		
	} root(fd);
	assert(&root.get_frame_section());
	opt<core::root_die&> opt_r = root; // for debugging
	
	/* Do we have an allocsites file for this object? If so, we incorporate its 
	 * synthetic data types. */
	auto allocsites = read_allocsites_for_binary(argv[1]);
	allocsites_relation_t allocsites_relation;
	multimap<string, iterator_df<type_die> > types_by_codeless_name;
	//set< pair<string, string> > to_generate_array0;
	if (allocsites)
	{
		/* rewrite the allocsites we were passed */
		merge_and_rewrite_synthetic_data_types(root, *allocsites);
	}
	get_types_by_codeless_uniqtype_name(types_by_codeless_name,
		root.begin(), root.end());
	if (allocsites)
	{
		make_allocsites_relation(allocsites_relation, *allocsites, types_by_codeless_name, root);
		cerr << "Allocsites relation contains " << allocsites_relation.size() << " data types." << endl;
	}

	struct subprogram_key : public pair< pair<string, string>, string > // ordering for free
	{
		subprogram_key(const string& subprogram_name, const string& sourcefile_name, 
			const string& comp_dir) : pair(make_pair(subprogram_name, sourcefile_name), comp_dir) {}
		string subprogram_name() const { return first.first; }
		string sourcefile_name() const { return first.second; }
		string comp_dir() const { return second; }
	};

	map<subprogram_key, iterator_df<subprogram_die> > subprograms_list;

	master_relation_t master_relation;
	make_exhaustive_master_relation(master_relation, root.begin(), root.end());

	cerr << "Master relation contains " << master_relation.size() << " data types." << endl;
	/* For each type we output a record:
	 * - a pointer to its name;
	 * - a length prefix;
	 * - a list of <offset, included-type-record ptr> pairs.
	 */

	// write a forward declaration for every uniqtype we need
	set<string> names_emitted;
	/* As a pre-pass, remember any ARR0 names we need. These need special handling,
	 * as flexible arrays with their make_precise members set. */
	map<string, pair<string, string> > arr0_needed_by_allocsites;
	for (auto i_site = allocsites_relation.begin(); i_site != allocsites_relation.end(); ++i_site)
	{
		auto objname = i_site->second.first.first;
		auto file_addr = i_site->second.first.second;
		string element_name_used_code = i_site->second.first.first;
		string element_name_used_ident = i_site->second.first.second;
		bool declare_as_array0 = i_site->second.second;
		
		if (declare_as_array0)
		{
			string element_mangled_name = mangle_typename(make_pair(element_name_used_code, element_name_used_ident));
			cout << "/* Allocation site type needed: ARR0 of " 
				<< element_mangled_name
				<< " */" << endl;
			
			string codeless_array_name = string("__ARR0_") + element_name_used_ident;
			string mangled_codeless_array_name
			 = mangle_typename(make_pair(string(""), codeless_array_name));
			arr0_needed_by_allocsites.insert(
				make_pair(mangled_codeless_array_name, 
					make_pair(element_mangled_name, codeless_array_name)
				)
			);
			
			// /* forward-declare it right now; we'll define it after everything else */
			// cout << "extern struct uniqtype " << mangled_codeless_array_name << ";" << endl;
			// /* pretend we've already emitted it... */
			// names_emitted.insert(mangled_codeless_array_name);
		}
	}
	map<string, set< iterator_df<type_die> > > types_by_name;
	
	write_master_relation(master_relation, cout, cerr, true /* emit_void */, true, 
		names_emitted, types_by_name, /* emit_codeless_alises */ true);
	
	// now write those pesky ARR0 ones -- any that we didn't emit earlier
	for (auto i_mangled_name = arr0_needed_by_allocsites.begin();
		i_mangled_name != arr0_needed_by_allocsites.end();
		++i_mangled_name)
	{
		const string& mangled_codeless_array_name = i_mangled_name->first;
		const string& element_mangled_name = i_mangled_name->second.first;
		const string& codeless_array_name = i_mangled_name->second.second;
		if (names_emitted.find(mangled_codeless_array_name) == names_emitted.end())
		{
			// we were intending to forestall the emission during the master relation
			// FIXME: there might be two cases here! want ARR0 and FLEXARR?
			// If we introduce FLEXARR, be sure to update symname-funcs.sh / translate_symnames
			// assert(names_emitted.find(mangled_array_name) == names_emitted.end());
			// This OBVIOUSLY doesn't work because we added to names_emitted!
			// Let the multiple definition error get us.
			// compute and print destination name
			write_uniqtype_open_flex_array(cout,
				mangled_codeless_array_name,
				/* array_codeless_name.second */ i_mangled_name->second.second
			);
			write_uniqtype_related_array_element_type(cout,
				i_mangled_name->second.first // i.e. the element type
			);

		write_uniqtype_close(cout, mangled_codeless_array_name);
		}
	}
	
	cerr << "Allocsites relation has " << allocsites_relation.size() << " members." << endl;
	for (auto i_site = allocsites_relation.begin(); i_site != allocsites_relation.end(); ++i_site)
	{
		auto objname = i_site->second.first.first;
		auto file_addr = i_site->second.first.second;
		string name_used_code = i_site->second.first.first;
		string name_used_ident = i_site->second.first.second;
		bool declare_as_array0 = i_site->second.second;
		
		if (!declare_as_array0)
		{
			cout << "/* Allocation site type not needing ARR0 type: " 
				<< i_site->second.first.second
				<< " */" << endl;
		} else cout << "/* We should have emitted a type of this name earlier: "
			<< name_used_ident << " */" << endl;
	}
	
	
	// now output for the subprograms
	cout << "/* Begin stack frame types. */" << endl;
	for (iterator_df<> i = root.begin(); i != root.end(); ++i)
	{
		if (i.is_a<subprogram_die>())
		{
			auto i_cu = i.enclosing_cu();
			
			iterator_df<subprogram_die> i_subp = i;
			// only add real, defined subprograms to the list
			if ( 
					( !i_subp->get_declaration() || !*i_subp->get_declaration() )
			   )
			{
				string sourcefile_name = i_subp->get_decl_file() ? 
					i_cu->source_file_name(*i_subp->get_decl_file())
					: "(unknown source file)";
				string comp_dir = i_cu->get_comp_dir() ? *i_cu->get_comp_dir() : "";

				string subp_name;
				if (i_subp.name_here()) subp_name = *i_subp.name_here();
				else 
				{
					std::ostringstream s;
					s << "0x" << std::hex << i_subp.offset_here();
					subp_name = s.str();
				}

				auto ret = subprograms_list.insert(
					make_pair(
						subprogram_key(subp_name, sourcefile_name, comp_dir), 
						i_subp
					)
				);
				if (!ret.second)
				{
					/* This means that "the same value already existed". */
					cerr << "Warning: subprogram " << *i_subp
						<< " already in subprograms_list as " 
						<< ret.first->first.subprogram_name() 
						<< " (in " 
						<< ret.first->first.sourcefile_name()
						<< ", compiled in " << ret.first->first.comp_dir()
						<< ")"
						<< endl;
				}
			}
		}
	}
	cerr << "Found " << subprograms_list.size() << " subprograms." << endl;
	
	/* For each subprogram, for each vaddr range for which its
	 * stack frame is laid out differently, output a uniqtype record.
	 * We do this by
	 * - collecting all local variables and formal parameters on a depthfirst walk;
	 * - collecting their vaddr ranges into a partition, splitting any overlapping ranges
	     and building a mapping from each range to the variables/parameters valid in it;
	 * - when we're finished, outputting a distinct uniqtype for each range;
	 * - also, output a table of IPs-to-uniqtypes. 
	 *
	 * We also output an allocsites record for each one, wit the allocsite as the
	 *  */

	
	typedef iterfirst_pair_hash< 
		with_dynamic_location_die, encap::loc_expr/* ,
		compare_first_iter_offset<encap::loc_expr> */
	>::set live_set_t;
	typedef boost::icl::interval_map< Dwarf_Off, live_set_t > intervals_t;
	typedef boost::icl::interval_map< 
			Dwarf_Off, 
			set<pair< 
					Dwarf_Signed, // frame offset
					iterator_df< with_dynamic_location_die >
				>,
				compare_first_signed_second_offset 
			>
		> frame_intervals_t;
	typedef boost::icl::interval_map< 
			Dwarf_Off, 
			iterfirst_pair_hash< 
				with_dynamic_location_die,
				string
			>::set/* ,
				compare_first_iter_offset<string> */
		> discarded_intervals_t;
		
	map< iterator_df<subprogram_die>, frame_intervals_t > intervals_by_subprogram;
	map< iterator_df<subprogram_die>, unsigned > frame_offsets_by_subprogram;
	
	using dwarf::core::with_static_location_die;
	
	for (auto i_i_subp = subprograms_list.begin(); i_i_subp != subprograms_list.end(); ++i_i_subp)
	{
		auto i_subp = i_i_subp->second;
		
		intervals_t subp_vaddr_intervals; // CU- or file-relative?

		/* Put this subp's vaddr ranges into the map */
		auto subp_intervals = i_subp->file_relative_intervals(
			root,
			[&i_subp, &root](const std::string&, void *) -> with_static_location_die::sym_binding_t {
				/* We need this symbol resolver because sometimes the DWARF info
				 * won't include a with-address-range entry for a function. I have
				 * seen this for external-definition-emmited C99 inline functions
				 * in gcc 7.2.x, but other cases are possible. */
				Dwarf_Off file_relative_start_addr; 
				Dwarf_Unsigned size;
				
				if (!i_subp.name_here()) throw No_entry();
				string s = *i_subp.name_here();
				
				auto symtab_etc = root.get_symtab();
				auto &symtab = symtab_etc.first.first;
				auto &strtab = symtab_etc.first.second;
				unsigned &n = symtab_etc.second;
				
				for (auto p = symtab; p < symtab + n; ++p)
				{
					if (p->st_name != 0 && string(strtab + p->st_name) == s)
					{
						return (with_static_location_die::sym_binding_t)
						{ p->st_value, p->st_size };
					}
				}
				
				throw No_entry();
				
			}, nullptr /* FIXME: write a symbol resolver -- do we need this? can just pass 0? */
		);

		core::iterator_df<> start_df(i_subp);
		unsigned subp_depth = start_df.depth();
		unsigned initial_depth = subp_depth;
		++start_df;
		
		struct iterator_bf_skipping_types : public core::iterator_bf<>
		{
			void increment()
			{
				if (spec_here().tag_is_type(tag_here()))
				{
					increment_skipping_subtree();
				} else increment();
			}			
			// forward constructors
			using core::iterator_bf<>::iterator_bf;
		} start_bf(start_df);
		
		for (auto i_bf = start_bf;
			i_bf != core::iterator_base::END
			&& (i_bf == start_bf || i_bf.depth() > initial_depth); 
			++i_bf)
		{
			// skip if not a with_dynamic_location_die
			if (!i_bf.is_a<with_dynamic_location_die>()) continue;

			/* Exploit "clever" (hopefully) aggregation semantics of 
			 * interval maps.
			 * http://www.boost.org/doc/libs/1_51_0/libs/icl/doc/html/index.html
			 */
			
			// enumerate the vaddr ranges of this DIE
			// -- note that some DIEs will be "for all vaddrs"
			// -- noting also that static variables need handling!
			//    ... i.e. they need to be handled in the *static* handler!
			
			// skip static variables
			if (i_bf.is_a<variable_die>() && i_bf.as_a<variable_die>()->has_static_storage())
			{
				/* FIXME: does sranges already deal with these? */
				continue;
			}
			auto i_dyn = i_bf.as_a<with_dynamic_location_die>();
			
			// skip member/inheritance DIEs
			if (i_dyn->location_requires_object_base()) continue;
			
			/* enumerate the vaddr ranges of this DIE
			 * -- note that some DIEs will be "for all vaddrs" */
			auto var_loclist = i_dyn->get_dynamic_location();
			// rewrite the loclist to use the CFA/frame_base maximally
			// cerr << "Saw loclist " << var_loclist << endl;
			var_loclist = encap::rewrite_loclist_in_terms_of_cfa(
				var_loclist, 
				root.get_frame_section(), 
				dwarf::spec::opt<const encap::loclist&>() /* opt_fbreg */
			);
			// cerr << "Rewrote to loclist " << var_loclist << endl;

			
			// for each of this variable's intervals, add it to the map
			int interval_index = 0;
			for (auto i_locexpr = var_loclist.begin(); 
				i_locexpr != var_loclist.end(); ++i_locexpr)
			{
				iterfirst_pair_hash< with_dynamic_location_die, encap::loc_expr >::set /*,
					compare_first_iter_offset<encap::loc_expr> */ singleton_set;
				/* PROBLEM: we need to remember not only that each i_dyn is valid 
				 * in a given range, but with what loc_expr. So we pair the i_dyn with
				 * the relevant loc_expr. */
				singleton_set.insert(make_pair(i_dyn, *i_locexpr));
				
				// FIXME: disgusting hack
				if (i_locexpr->lopc == 0xffffffffffffffffULL
				|| i_locexpr->lopc == 0xffffffffUL)
				{
					// we got a base address selection entry -- not handled yet
					assert(false);
				}
				
				if (i_locexpr->lopc == i_locexpr->hipc && i_locexpr->hipc != 0) continue; // skip empties
				if (i_locexpr->hipc <  i_locexpr->lopc)
				{
					cerr << "Warning: lopc (0x" << std::hex << i_locexpr->lopc << std::dec
						<< ") > hipc (0x" << std::hex << i_locexpr->hipc << std::dec << ")"
						<< " in " << *i_dyn << endl;
					continue;
				}
				
				/* vaddrs in this CU are relative to what addr? 
				 * If we're an executable, they're absolute. 
				 * If we're a shared library, they should be relative to its load address. */
				auto opt_cu_base = i_subp.enclosing_cu()->get_low_pc();
				if (!opt_cu_base)
				{
					cerr << "Warning: skipping subprogram " << *i_dyn 
						<< " -- in CU with no base address (CU: "
						<< *i_subp.enclosing_cu()
						<< ")" << endl;
					continue;
				}
				Dwarf_Unsigned cu_base = opt_cu_base->addr;
				
				// handle "for all vaddrs" entries
				boost::icl::discrete_interval<Dwarf_Off> our_interval;
				auto print_sp_expr = [&our_interval, &root]() {
					/* Last question. What's the stack pointer in terms of the 
					 * CFA? We can answer this question by faking up a location
					 * list referring to the stack pointer, and asking libdwarfpp
					 * to rewrite that.*/
					cerr << "Calculating rewritten-SP loclist..." << endl;
					auto sp_loclist = encap::rewrite_loclist_in_terms_of_cfa(
						encap::loclist(dwarf_stack_pointer_expr_for_elf_machine(
							root.get_frame_section().get_elf_machine(),
							our_interval.lower(), 
							our_interval.upper()
						)),
						root.get_frame_section(), 
						dwarf::spec::opt<const encap::loclist&>() /* opt_fbreg */
					);
					cerr << "Got SP loclist " << sp_loclist << endl;
					
					/* NOTE: I abandoned the above approach because it doesn't yield
					 * a fixed offset to the SP in general. One reason why not is
					 * alloca(). Other frames might also do weird dynamic sp adjustments
					 * not captured in the unwind information. The Right Fix is to store
					 * one offset per frame, recording the biggest negative offset such 
					 * that all frame elements start at a nonnegative offset from that. */
				};
				if (i_locexpr->lopc == 0 && 0 == i_locexpr->hipc
					|| i_locexpr->lopc == 0 && i_locexpr->hipc == std::numeric_limits<Dwarf_Off>::max())
				{
					// if we have a "for all vaddrs" entry, we should be the only index
					assert(interval_index == 0);
					assert(i_locexpr + 1 == var_loclist.end());
					
					/* we will just add the intervals of the containing subprogram */
					auto subp_intervals = i_subp->file_relative_intervals(root, nullptr, nullptr);
					for (auto i_subp_int = subp_intervals.begin();
						i_subp_int != subp_intervals.end(); 
						++i_subp_int)
					{
						/* NOTE: we do *not* adjust these by cu_base. This has already 
						 * been done, by file_relative_intervals! */
						our_interval = boost::icl::interval<Dwarf_Off>::right_open(
							i_subp_int->first.lower()/* + cu_base*/,
							i_subp_int->first.upper()/* + cu_base*/
						);
						
						cerr << "Borrowing vaddr ranges of " << *i_subp
							<< " for dynamic-location " << *i_dyn << endl;
						
						/* assert sane interval */
						assert(our_interval.lower() < our_interval.upper());
						/* assert sane size -- no bigger than biggest sane function */
						assert(our_interval.upper() - our_interval.lower() < 1024*1024);
						subp_vaddr_intervals += make_pair(
							our_interval,
							singleton_set
						);
						
						// print_sp_expr();
					}
					/* There should be only one entry in the location list if so. */
					assert(i_locexpr == var_loclist.begin());
					assert(i_locexpr + 1 == var_loclist.end());
				}
				else /* we have nonzero lopc and/or hipc */
				{
					/* We *do* have to adjust these by cu_base, because 
					 * we're getting them straight from the location expression. */
					our_interval = boost::icl::interval<Dwarf_Off>::right_open(
						i_locexpr->lopc + cu_base, i_locexpr->hipc + cu_base
					); 
					
					// cerr << "Considering location of " << i_dyn << endl;
					
					/* assert sane interval */
					assert(our_interval.lower() < our_interval.upper());
					/* assert sane size -- no bigger than biggest sane function */
					assert(our_interval.upper() - our_interval.lower() < 1024*1024);
					subp_vaddr_intervals += make_pair(
						our_interval,
						singleton_set
					);
					
					// print_sp_expr();
				}
			}
			
			/* We note that the map is supposed to map file-relative addrs
			 * (FIXME: vaddr is CU- or file-relative? or "applicable base address" blah?) 
			 * to the set of variable/fp DIEs that are 
			 * in the current (top) stack frame when the program counter is at that vaddr. */

		} /* end bfs */

		/* Now we write a *series* of object layouts for this subprogram, 
		 * discriminated by a set of (disjoint) vaddr ranges. */
		
		/* Our naive earlier algorithm had the problem that, once register-based 
		 * locals are discarded, the frame layout is often unchanged from one vaddr range
		 * to the next. But we were outputting a new uniqtype anyway, creating 
		 * huge unnecessary bloat. So instead, we do a pre-pass where we remember
		 * only the stack-located elements, and store them in a new interval map, 
		 * by offset from frame base. 
		 *
		 * Also, we want to report discarded fps/locals once per subprogram, as 
		 * completely discarded or partially discarded. How to do this? 
		 * Keep an interval map of discarded items.
		 * When finished, walk it and build another map keyed by 
		  */
		frame_intervals_t frame_intervals;
		discarded_intervals_t discarded_intervals;
		 
		for (auto i_int = subp_vaddr_intervals.begin(); 
			i_int != subp_vaddr_intervals.end(); ++i_int)
		{
			/* Get the set of <p_dyn, locexpr>s for this vaddr range. */
			auto& frame_elements = i_int->second;
			
			/* Calculate their offset from the frame base, and sort. */
			//std::map<Dwarf_Signed, shared_ptr<with_dynamic_location_die > > by_frame_off;
			//std::vector<pair<shared_ptr<with_dynamic_location_die >, string> > discarded;

			/* We used to check that we don't see the same DIE twice within the same interval.
			 * But WHY? We could have two pairs in frame_elements, with different loc_exprs.
			 * In fact this does happen. So I've deleted the check. */
			for (auto i_el_pair = frame_elements.begin(); i_el_pair != frame_elements.end(); ++i_el_pair)
			{
				/* Note that thanks to the aggregation semantics of subp_vaddr_intervals, 
				 * i_int is already the intersection of the loc_expr interval *and* all
				 * other loc_expr intervals in use within this subprogram. W*/

				/* NOTE: our offset can easily be negative! For parameters, it 
				 * usually is. So we calculate the offset from the middle of the 
				 * (imaginary) address space, a.k.a. 1U<<((sizeof(Dwarf_Addr)*8)-1). 
				 * In a signed two's complement representation, 
				 * this number is -MAX. 
				 * NO -- just reinterpret_cast to a signed? */
				
				auto i_el = &i_el_pair->first;
				
				Dwarf_Addr addr_from_zero;
				/* Check for vars that are part static, part on-stack. 
				 * How does this happen? One example is 
				 * the 'git_packed' that is local within rearrange_packed_git
				 * which gets inlined into prepare_packed_git in sha1_file.c.
				 * 
				 * The answer is: they're static vars that are being manipulated
				 * locally within the function. Because they're "variables" that are
				 * "in scope" (I think this is an interaction with inlining), 
				 * they get their own DW_TAG_variable DIEs within the inlined 
				 * instance's DWARF. While they're being manipulated, these have 
				 * register locations. It would be pointless to spill them to the 
				 * stack, however, so I don't think we need to worry about them. */
				if (i_el_pair->second.size() > 0 && i_el_pair->second.at(0).lr_atom == DW_OP_addr
				 && i_el_pair->second.at(i_el_pair->second.size() - 1).lr_atom != DW_OP_stack_value)
				{
					cerr << "Skipping static var masquerading as local: "
						<< *i_el 
						<< "in the vaddr range " 
						<< std::hex << i_int->first << std::dec << std::endl;
					iterfirst_pair_hash< with_dynamic_location_die, string>::set /*,
						compare_first_iter_offset<string>*/ singleton_set;
					singleton_set.insert(make_pair(*i_el, string("static-masquerading-as-local")));
					discarded_intervals += make_pair(i_int->first, singleton_set);
					continue;
				}
				
				bool saw_register = false;
				auto& spec = i_el_pair->first.spec_here();
				for (auto i_instr = i_el_pair->second.begin(); i_instr != i_el_pair->second.end();
					++i_instr)
				{
					if (spec.op_reads_register(i_instr->lr_atom))
					{ saw_register = true; break; }
				}
				
				/* FIXME: DW_OP_piece complicates this. If we have part in a register, 
				 * part on the stack, we'd like to record this somehow. Perhaps supply
				 * a getter and setter in the make_precise()-generated uniqtype? */
				
				if (saw_register)
				{
					/* This means our variable/fp is in a register and not 
					 * in a stack location. That's fine. Warn and continue. */
					if (debug_out > 1)
					{
						cerr << "Warning: we think this is a register-located local/fp or pass-by-reference fp "
							<< "in the vaddr range " 
							<< std::hex << i_int->first << std::dec
							<< ": "
					 		<< *i_el;
					}
					//discarded.push_back(make_pair(*i_el, "register-located"));
					iterfirst_pair_hash< with_dynamic_location_die, string>::set/*,
						compare_first_iter_offset<string> */ singleton_set;
					singleton_set.insert(make_pair(*i_el, string("register-located")));
					discarded_intervals += make_pair(i_int->first, singleton_set);
					continue;
				}
				else try
				{
					std::stack<Dwarf_Unsigned> initial_stack; 
					// call the evaluator directly
					// -- push zero (a.k.a. the frame base) onto the initial stack
					initial_stack.push(0); 
					// FIXME: really want to push the offset of the stack pointer from the frame base
					dwarf::expr::evaluator e(i_el_pair->second,
						i_el_pair->first.spec_here(),
						/* fb */ 0, 
						initial_stack);
					addr_from_zero = e.tos(false); // may *not* be value; must be loc
				} 
				catch (dwarf::lib::No_entry)
				{
					/* Not sure what would cause this, since we scanned for registers. */
					if (debug_out > 1)
					{
						cerr << "Warning: failed to locate non-register-located local/fp "
							<< "in the vaddr range " 
							<< std::hex << i_int->first << std::dec
							<< ": "
					 		<< *i_el;
					}
					//discarded.push_back(make_pair(*i_el, "register-located"));
					iterfirst_pair_hash< with_dynamic_location_die, string>::set/*,
						compare_first_iter_offset<string> */ singleton_set;
					singleton_set.insert(make_pair(*i_el, string("unknown")));
					discarded_intervals += make_pair(i_int->first, singleton_set);
					continue;
				}
				catch (...)
				{
					cerr << "Warning: something strange happened when computing location for fp: " 
					 	<< *i_el;
					//discarded.push_back(make_pair(*i_el, "register-located"));
					iterfirst_pair_hash< with_dynamic_location_die, string>::set /*,
						compare_first_iter_offset<string> */ singleton_set;
					singleton_set.insert(make_pair(*i_el, string("something-strange")));
					discarded_intervals += make_pair(i_int->first, singleton_set);
					continue;
				}
				Dwarf_Signed frame_offset = static_cast<Dwarf_Signed>(addr_from_zero);
				// cerr << "Found on-stack location (fb + " << frame_offset << ") for fp/var " << *i_el 
				// 		<< "in the vaddr range " 
				// 		<< std::hex << i_int->first << std::dec << endl;

				/* We only add to by_frame_off if we have complete type => nonzero length. */
				if ((*i_el)->find_type() && (*i_el)->find_type()->get_concrete_type())
				{
					//by_frame_off[frame_offset] = *i_el;
					set< pair< Dwarf_Signed, iterator_df< with_dynamic_location_die > >,
						compare_first_signed_second_offset > singleton_set;
					singleton_set.insert(make_pair(frame_offset, *i_el));
					frame_intervals += make_pair(i_int->first, singleton_set);
				}
				else
				{
					iterfirst_pair_hash< with_dynamic_location_die, string>::set/*,
						compare_first_iter_offset<string> */ singleton_set;
					singleton_set.insert(make_pair(*i_el, string("no_concrete_type")));
					discarded_intervals += make_pair(i_int->first, singleton_set);
				}
			}
		} /* end for i_int */
		
		intervals_by_subprogram[i_subp] = frame_intervals;
		if (frame_intervals.size() == 0)
		{
			cerr << "Warning: no frame element intervals for subprogram " << i_subp << endl;
		}
		
		/* Now figure out the positive and negative extents of the frame. */
		typedef decltype(frame_intervals) is_t;
		std::map< is_t::key_type, unsigned> interval_maxoffs;
		std::map< is_t::key_type, signed>   interval_minoffs;
		signed overall_frame_minoff = 0;
		for (auto i_frame_int = frame_intervals.begin(); i_frame_int != frame_intervals.end();
			++i_frame_int)
		{
			unsigned interval_maxoff;
			signed interval_minoff;
			//if (by_frame_off.begin() == by_frame_off.end()) frame_size = 0;
			if (i_frame_int->second.size() == 0) { interval_maxoff = 0; interval_minoff = 0; }
			else
			{
				{
					frame_intervals_t::codomain_type::iterator i_maxoff_el = i_frame_int->second.end(); --i_maxoff_el;
// 					Dwarf_Signed seen_maxoff = std::numeric_limits<Dwarf_Signed>::min();
// 					for (auto i_el = i_frame_int->second.begin(); i_el != i_frame_int->second.end(); ++i_el)
// 					{
// 						if (i_el->first > seen_maxoff)
// 						{
// 							seen_maxoff = i_el->first;
// 							i_maxoff_el = i_el;
// 						}
// 					}
					auto p_maxoff_type = i_maxoff_el->second->find_type();
					unsigned calculated_maxel_size;
					if (!p_maxoff_type || !p_maxoff_type->get_concrete_type()) 
					{
						cerr << "Warning: found local/fp with no type  (assuming zero length): " 
							<< *i_maxoff_el->second;
						calculated_maxel_size = 0;
					}
					else 
					{
						opt<Dwarf_Unsigned> opt_size = p_maxoff_type->calculate_byte_size();
						if (!opt_size)
						{
							cerr << "Warning: found local/fp with no size (assuming zero length): " 
								<< *i_maxoff_el->second;
							calculated_maxel_size = 0;						
						} else calculated_maxel_size = *opt_size;
					}
					signed interval_max_offset = i_maxoff_el->first + calculated_maxel_size;
					interval_maxoff = (interval_max_offset < 0) ? 0 : interval_max_offset;
				}
				{
					auto i_minoff_el = i_frame_int->second.begin();
					signed interval_min_offset = i_minoff_el->first;
					interval_minoff = (interval_min_offset > 0) ? 0 : interval_min_offset;
				}
			}
			
			interval_maxoffs.insert(make_pair(i_frame_int->first, interval_maxoff));
			interval_minoffs.insert(make_pair(i_frame_int->first, interval_minoff));
			if (interval_minoff < overall_frame_minoff) overall_frame_minoff = interval_minoff;
		}
		unsigned offset_to_all = 0;
		if (overall_frame_minoff < 0)
		{
			/* The offset we want to apply to everything is the negation of 
			 * overall_frame_minoff, rounded *up* to a word. */
			// FIXME: don't assume host word size
			unsigned remainder = (-overall_frame_minoff) % (sizeof (void*));
			unsigned quotient  = (-overall_frame_minoff) / (sizeof (void*));
			offset_to_all =
				remainder == 0 ? quotient * (sizeof (void*))
					: (quotient + 1) * (sizeof (void*));
		}
		frame_offsets_by_subprogram[i_subp] = offset_to_all;
		
		/* Now for each distinct interval in the frame_intervals map... */
		for (auto i_frame_int = frame_intervals.begin(); i_frame_int != frame_intervals.end();
			++i_frame_int)
		{
			auto found_maxoff = interval_maxoffs.find(i_frame_int->first);
			assert(found_maxoff != interval_maxoffs.end());
			unsigned interval_maxoff = found_maxoff->second;
			auto found_minoff = interval_minoffs.find(i_frame_int->first);
			assert(found_minoff != interval_minoffs.end());
			signed interval_minoff = found_minoff->second;
			
			/* Output in offset order, CHECKing that there is no overlap (sanity). */
			cout << "\n/* uniqtype for stack frame ";
			string unmangled_typename = typename_for_vaddr_interval(i_subp, i_frame_int->first);
			
			string cu_name = *i_subp.enclosing_cu().name_here();
			
			cout << unmangled_typename
				 << " defined in " << cu_name << ", "
				 << "vaddr range " << std::hex << i_frame_int->first << std::dec << " */\n";
			ostringstream min_s; min_s << "actual min is " << interval_minoff + offset_to_all;
			string mangled_name = mangle_typename(make_pair(cu_name, unmangled_typename));
			write_uniqtype_open_composite(cout,
				mangled_name,
				unmangled_typename,
				interval_maxoff + offset_to_all,
				i_frame_int->second.size(),
				false,
				min_s.str()
			);
			for (auto i_by_off = i_frame_int->second.begin(); i_by_off != i_frame_int->second.end(); ++i_by_off)
			{
				ostringstream comment_s;
				if (i_by_off->second.name_here())
				{
					comment_s << *i_by_off->second.name_here();
				}
				else comment_s << "(anonymous)"; 
				comment_s << " -- " << i_by_off->second.spec_here().tag_lookup(
						i_by_off->second.tag_here())
					<< " @" << std::hex << i_by_off->second.offset_here() << std::dec;

				string mangled_name = mangle_typename(canonical_key_for_type(i_by_off->second->find_type()));
				assert(names_emitted.find(mangled_name) != names_emitted.end());
				
				write_uniqtype_related_contained_member_type(cout,
					/* is_first */ i_by_off == i_frame_int->second.begin(),
					i_by_off->first + offset_to_all,
					mangled_name,
					comment_s.str()
				);
			}
			write_uniqtype_close(cout, mangled_name);
		}
		/* Now print a summary of what was discarded. */
// 		for (auto i_discarded = discarded.begin(); i_discarded != discarded.end(); 
// 			++i_discarded)
// 		{
// 			cout << "\n\t/* discarded: ";
// 			if (i_discarded->first.name_here())
// 			{
// 				cout << *i_discarded->first.name_here();
// 			}
// 			else cout << "(anonymous)"; 
// 			cout << " -- " << i_discarded->first->get_spec().tag_lookup(
// 					i_discarded->first->get_tag())
// 				<< " @" << std::hex << i_discarded->first->get_offset() << std::dec;
// 			cout << "; reason: " << i_discarded->second;
// 			cout << " */ ";
// 		}
	} // end for subprogram
	
	/* Now write frame_vaddr allocsites. */
	cout << "struct allocsite_entry\n\
{ \n\
	void *next; \n\
	void *prev; \n\
	void *allocsite; \n\
	struct uniqtype *uniqtype; \n\
};\n";
	cout << "struct frame_allocsite_entry\n\
{ \n\
	unsigned offset_from_frame_base;\n\
	struct allocsite_entry entry;\n\
};\n";
	cout << "struct static_allocsite_entry\n\
{ \n\
	const char *name;\n\
	struct allocsite_entry entry;\n\
};\n";
	cout << "struct frame_allocsite_entry frame_vaddrs[] = {" << endl;

	unsigned total_emitted = 0;
	
	/* NOTE: our allocsite chaining trick in liballocs requires that our allocsites 
	 * are sorted in vaddr order, so that adjacent allocsites in the memtable buckets
	 * are adjacent in the table. So we sort them here. */
	set< pair< boost::icl::discrete_interval<Dwarf_Addr>, iterator_df<subprogram_die> > > sorted_intervals;
	for (map< iterator_df<subprogram_die>, frame_intervals_t >::iterator i_subp_intervals 
	  = intervals_by_subprogram.begin(); i_subp_intervals != intervals_by_subprogram.end();
	  ++ i_subp_intervals)
	{
		// now output an allocsites-style table for these 
		for (auto i_int = i_subp_intervals->second.begin(); i_int != i_subp_intervals->second.end(); 
			++i_int)
		{
			sorted_intervals.insert(make_pair(i_int->first, i_subp_intervals->first));
		}
	}
	
	for (auto i_pair = sorted_intervals.begin(); i_pair != sorted_intervals.end(); ++i_pair)
	{
		unsigned offset_from_frame_base = frame_offsets_by_subprogram[i_pair->second];
	
		cout << "\n\t/* frame alloc record for vaddr 0x" << std::hex << i_pair->first.lower() 
			<< "+" << i_pair->first.upper() << std::dec << " */";
		cout << "\n\t{\t" << offset_from_frame_base << ","
			<< "\n\t\t{ (void*)0, (void*)0, "
			<< "(char*) " << "0" // will fix up at load time
			<< " + " << i_pair->first.lower() << "UL, " 
			<< "&" << mangle_typename(make_pair(*i_pair->second.enclosing_cu().name_here(),
				typename_for_vaddr_interval(i_pair->second, i_pair->first)))
			<< " }"
			<< "\n\t}";
		cout << ",";
		++total_emitted;
	}
	// output a null terminator entry
	cout << "\n\t{ 0, { (void*)0, (void*)0, (void*)0, (struct uniqtype *)0 } }";
	
	// close the list
	cout << "\n};\n";

	/* Now write static allocsites. As above, we also have to sort them. */
	set<pair< Dwarf_Addr, iterator_df<program_element_die> > > sorted_statics;

	for (auto i = root.begin(); i != root.end(); ++i)
	{
		cerr << i.summary() << std::endl;
		boost::icl::interval_map<Dwarf_Addr, Dwarf_Unsigned> intervals;
		if (i.tag_here() == DW_TAG_variable
			&& i.has_attribute_here(DW_AT_location))
			
		{
			if (!i.as_a<variable_die>()->has_static_storage())
			{
				// cerr << "Skipping non-static var " << i.summary() << std::endl;
				continue;
			}
			iterator_df<variable_die> i_var = i.as_a<variable_die>();
			try
			{
				intervals = 
					i_var->file_relative_intervals(
						root, 
						0 /* sym_binding_t (*sym_resolve)(const std::string& sym, void *arg) */, 
						0 /* arg */);
			}
			catch (dwarf::lib::No_entry)
			{
				// this happens if we don't have a real location -- continue
				continue;
			}
		}
		else if (i.is_a<subprogram_die>())
		{
			try
			{
				intervals = 
					i.as_a<subprogram_die>()->file_relative_intervals(
						root, 
						0 /* sym_binding_t (*sym_resolve)(const std::string& sym, void *arg) */, 
						0 /* arg */);
			}
			catch (dwarf::lib::No_entry)
			{
				// this happens if we don't have a real location -- continue
				continue;
			}
		}
		if (intervals.size() == 0)
		{
			// this happens if we don't have a real location -- continue
			continue;
		}

		// calculate its file-relative addr
		Dwarf_Off addr = intervals.begin()->first.lower();

		sorted_statics.insert(make_pair(addr, i.as_a<program_element_die>()));
	}
	
	cout << "struct static_allocsite_entry statics[] = {" << endl;
	
	for (auto i_var_pair = sorted_statics.begin(); i_var_pair != sorted_statics.end(); ++i_var_pair)
	{
		auto addr = i_var_pair->first;
		auto& i_var = i_var_pair->second;
		
		/* Addr 0 is problematic. It generally refers to thinks that aren't really 
		 * there, like weak symbols (that somehow have debug info) or __evoke_link_warning_*
		 * things. But it could also be a legitimate vaddr. Hmm. Well, skip it for now.
		 * If we leave it, the addr lookup function becomes ambiguous if there are many
		 * allocs at address zero, and this confuses us (e.g. our assertion after chaining
		 * allocsites). FIXME: better to filter out based on the *type* of the thing? */
		if (addr == 0) continue;

		ostringstream anon_name; anon_name << "0x" << std::hex << i_var.offset_here();

		cout << "\n\t/* static alloc record for object "
			 << (i_var.name_here() ? *i_var.name_here() : ("anonymous, DIE " + anon_name.str())) 
			 << " at vaddr " << std::hex << "0x" << addr << std::dec << " */";
		ostringstream name_token;
		if (i_var.name_here()) name_token << "\"" << cxxgen::escape(*i_var.name_here()) << "\"";
		else name_token << "(void*)0";
		cout << "\n\t{ " << name_token.str() << ","
			<< "\n\t  { (void*)0, (void*)0, "
			<< "(char*) " << "0" // will fix up at load time
			<< " + " << addr << "UL, " 
			<< "&" << mangle_typename(canonical_key_for_type(
				i_var.is_a<subprogram_die>() ? i_var.as_a<type_die>() : i_var.as_a<variable_die>()->find_type()))
			<< " }\n\t}";
		cout << ",";
	}

	// output a null terminator entry
	cout << "\n\t{ (void*)0, { (void*)0, (void*)0, (void*)0, (struct uniqtype *)0 } }";
	
	// close the list
	cout << "\n};\n";


	// success! 
	return 0;
}

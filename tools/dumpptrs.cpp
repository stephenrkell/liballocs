/* This is a simple dwarfpp program which generates a C file
 * recording data on a uniqued set of data types  allocated in a given executable.
 */
 
#include <fstream>
#include <sstream>
#include <map>
#include <set>
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
#include <gelf.h>

#include "helpers.hpp"
#include "uniqtypes.hpp"

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
using dwarf::core::Fde;
using dwarf::core::Cie;
using dwarf::core::FrameSection;

using namespace dwarf::lib;

// regex usings
using boost::regex;
using boost::regex_match;
using boost::smatch;
using boost::regex_constants::egrep;
using boost::match_default;
using boost::format_all;
using boost::icl::interval_map;

template<typename _Key, typename _Compare = std::less<_Key>,
	   typename _Alloc = std::allocator<_Key> >
bool sanity_check_set(const std::set<_Key, _Compare, _Alloc>& s)
{
	unsigned count = 0;
	for (auto i = s.begin(); i != s.end(); ++i, ++count);
	return count == s.size();
}

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

static string ptrs_typename(const pair<string, string>& strs)
{
	string s = mangle_typename(strs);
	return boost::replace_first_copy(s, "__uniqtype_","__ptrs_");
}

// FIXME: other CPUs/ABIs
bool is_callee_save_register(int col)
{
	return col == DWARF_X86_64_RBX
	    || col == DWARF_X86_64_RBP
	    || col == DWARF_X86_64_R12
	    || col == DWARF_X86_64_R13
	    || col == DWARF_X86_64_R14
	    || col == DWARF_X86_64_R15;
}

static int debug_out = 1;

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
	
	if (getenv("DUMPPTRS_DEBUG"))
	{
		debug_out = atoi(getenv("DUMPPTRS_DEBUG"));
	}
	
	using core::root_die;
	struct sticky_root_die : public root_die
	{
		using root_die::root_die;
		
		// virtual bool is_sticky(const core::abstract_die& d) { return true; }
		
	} root(fileno(infstream));
	assert(&root.get_frame_section());
	opt<core::root_die&> opt_r = root; // for debugging

	struct subprogram_key : public pair< pair<string, string>, string > // ordering for free
	{
		subprogram_key(const string& subprogram_name, const string& sourcefile_name, 
			const string& comp_dir) : pair(make_pair(subprogram_name, sourcefile_name), comp_dir) {}
		string subprogram_name() const { return first.first; }
		string sourcefile_name() const { return first.second; }
		string comp_dir() const { return second; }
	};

	map<subprogram_key, iterator_df<subprogram_die> > subprograms_list;
	interval_map< Dwarf_Addr, std::set< iterator_df<subprogram_die> > > subprogram_intervals;
	
	// now output for the subprograms
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
				std::set< iterator_df<subprogram_die> > singleton_set;
				singleton_set.insert(i_subp);
				
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
				
				/* Remember the address range of this subprogram */
				auto subp_intervals = i_subp->file_relative_intervals(root, nullptr, nullptr);
				
				for (auto i_subp_int = subp_intervals.begin();
					i_subp_int != subp_intervals.end(); 
					++i_subp_int)
				{
					assert(i_subp_int->first.upper() >= i_subp_int->first.lower());
					
					/* NOTE: we do *not* adjust these by cu_base. This has already 
					 * been done, by file_relative_intervals! */
					auto our_interval = boost::icl::interval<Dwarf_Off>::right_open(
						i_subp_int->first.lower(),
						i_subp_int->first.upper()
					);
					subprogram_intervals += make_pair(
						our_interval,
						singleton_set
					);
					
					cerr << "Added range within subprogram ";
					if (i_subp.name_here()) cerr << *i_subp.name_here();
					else cerr << "0x" << std::hex << i_subp.offset_here() << std::dec;
					cerr << ": [" << std::hex << i_subp_int->first.lower() << ", "
					     << i_subp_int->first.upper() << std::dec << ")" << std::endl;
				}
			}
		}
	}
	cerr << "Found " << subprograms_list.size() << " subprograms." << endl;
	
	/* For each subprogram, collect all local variables and formal parameters on a 
	 * depthfirst walk; keep those whose type matches a predicate (roughly "is a pointer").
	 */
	using dwarf::lib::Dwarf_Off;
	using dwarf::lib::Dwarf_Addr;
	using dwarf::lib::Dwarf_Signed;
	using dwarf::lib::Dwarf_Unsigned;
	
	// we can represent save locations that are "in register number X" or "on stack at offset Y"
	struct store_location : pair< int, Dwarf_Signed >
	{
		using pair::pair;
		const int& regnum() const { return this->first; }
		      int& regnum()       { return this->first; }
		const Dwarf_Signed& cfa_offset() const { if (this->regnum() == -1) return this->second; else throw No_entry(); }
		      Dwarf_Signed& cfa_offset()       { if (this->regnum() == -1) return this->second; else throw No_entry(); }
		
		store_location(int regnum) : pair(regnum, -1) {}
		store_location() : pair(-1, -1) {}
	};
	
	struct saved_caller_register : pair < int, store_location >
	{
		// NOTE: can save a register in a register, sometimes, so second is store_location
		using pair::pair;
		
		const int& regnum() const { return this->first; }
		      int& regnum()       { return this->first; }
		const store_location& saved_location() const { return this->second; }
		      store_location& saved_location()       { return this->second; }
	};
	
	struct retained_element
	{
		bool is_local; // else is reg
		store_location loc;
		iterator_df<with_dynamic_location_die> local_die; // if any
		int reg; // else -1
		
		/* Simple lexicographic ordering -- but we want to make sure that 
		 * they are sorted by stack offset*/
		bool operator<(const struct retained_element& arg) const
		{
			return loc < arg.loc
			|| (loc == arg.loc && is_local && arg.is_local && local_die < arg.local_die)
			|| (loc == arg.loc && !is_local && !arg.is_local && reg < arg.reg);
		}
		bool operator==(const struct retained_element& arg) const
		{
			return loc == arg.loc
				&& (is_local ? local_die == arg.local_die : reg == arg.reg);
		}
		bool operator!=(const struct retained_element& arg) const { return !(*this == arg); }
		bool operator<=(const struct retained_element& arg) const { return *this == arg || *this < arg; }
		bool operator>=(const struct retained_element& arg) const { return !(*this < arg); }
		bool operator> (const struct retained_element& arg) const { return *this != arg && *this >= arg; }
		
		retained_element(const store_location& local_loc,
			iterator_df<with_dynamic_location_die> i_d) : is_local(true), loc(local_loc), local_die(i_d) {}
		retained_element(const store_location& loc, int reg) : is_local(false), loc(loc), reg(reg)
		{ assert(reg != -1); }
	};
	
	typedef std::set< pair< iterator_df<with_dynamic_location_die>, encap::loc_expr > > live_set_t;
	typedef boost::icl::interval_map< Dwarf_Off, live_set_t > intervals_t;
	typedef boost::icl::interval_map< 
			Dwarf_Off, 
			std::set< 
			retained_element
			> 
		> retained_intervals_t;
	typedef boost::icl::interval_map< 
			Dwarf_Off, 
			std::set< 
				pair<
					iterator_df<with_dynamic_location_die>,
					string
				>
			>
		> discarded_intervals_t;
	
	typedef FrameSection::fde_iterator fde_iterator;
	
	map< iterator_df<subprogram_die>, retained_intervals_t > intervals_by_subprogram;
	map< iterator_df<subprogram_die>, unsigned > frame_offsets_by_subprogram;
	map< iterator_df<subprogram_die>, vector<fde_iterator> > fdes_by_subprogram;
	
	// walk over FDEs and group by subprogram
	GElf_Ehdr ehdr;
	GElf_Ehdr *ret = gelf_getehdr(root.get_elf(), &ehdr);
	assert(ret != 0);
	auto elf_machine = ehdr.e_machine;
	FrameSection fs(root.get_dbg(), true);

	typedef FrameSection::cie_iterator cie_iterator;
	typedef FrameSection::fde_iterator fde_iterator;
	
	/* Walk the FDEs. For each FDE, find which subprogram(s) overlap it, and chalk
	 * it up on fdes_by_subprogram. */
	for (auto i_fde = fs.fde_begin(); i_fde != fs.fde_end(); ++i_fde)
	{
		Dwarf_Addr fde_lopc = i_fde->get_low_pc();
		Dwarf_Addr fde_hipc = i_fde->get_low_pc() + i_fde->get_func_length();
		auto fde_interval = boost::icl::interval<Dwarf_Addr>::right_open(fde_lopc, fde_hipc);
		
		cerr << "Considering FDE beginning 0x" << std::hex << fde_lopc << std::dec << endl;
		
		/* Enumerate the overlapping subprograms. Warn if the count is not
		 * exactly 1. */
		auto i = subprogram_intervals.find(fde_lopc);
		for (; i != subprogram_intervals.end() && i->first.lower() < fde_hipc; ++i)
		{
			if (i->second.size() != 1)
			{
				cerr << "Warning: over interval (" << std::hex << i->first.lower()
					<< ", " << i->first.upper() << "]" << std::dec
					<< ", found " << i->second.size() << " subprograms: {";
			}
			for (auto i_s = i->second.begin(); i_s != i->second.end(); ++i_s)
			{
				cerr << "Found overlap with subprogram ";
				if (i_s->name_here()) cerr << *i_s->name_here();
				else cerr << "0x" << std::dec << i_s->offset_here() << std::dec;
				cerr << endl;

				fdes_by_subprogram[*i_s].push_back(i_fde);
				
				if (i->second.size() != 1)
				{
					if (i_s != i->second.begin()) cerr << ", ";
					cerr << *i_s;
				}
			}
			if (i->second.size() != 1) cout << " }" << endl;
		}
	}
	
	cout << "struct ucontext;\n"
"struct stored_ptrs\n"
"{\n"
"	unsigned long low_addr;\n"
"	unsigned long high_addr;\n"
"	unsigned nstored;\n"
"	struct stored\n"
"	{\n"
"		enum what_stored_t { LOCAL, CALLER_REG } what;\n"
"		union\n"
"		{\n"
"			struct\n"
"			{\n"
"				const char *name;\n"
"			} local;\n"
"			struct\n"
"			{\n"
"				unsigned num;\n"
"			} caller_reg;\n"
"		} what_info;\n"
"		enum where_stored_t { REG, STACK, NON_MANIFEST } where;\n"
"		union\n"
"		{\n"
"			struct\n"
"			{\n"
"				unsigned num;\n"
"			} reg;\n"
"			struct\n"
"			{\n"
"				signed cfa_offset;\n"
"			} stack;\n"
"			struct\n"
"			{\n"
"				unsigned long (*compute)(struct ucontext *ctxt);\n"
"			} non_manifest;\n"
"			\n"
"		} where_info;\n"
"	} stored[];\n"
"};\n";

	
	for (auto i_i_subp = subprograms_list.begin(); i_i_subp != subprograms_list.end(); ++i_i_subp)
	{
		auto i_subp = i_i_subp->second;
		
		intervals_t subp_vaddr_intervals; // CU- or file-relative?

		/* Put this subp's vaddr ranges into the map */
		//auto subp_intervals = i_subp->file_relative_intervals(
		//	root, 
		//	nullptr, nullptr /* FIXME: write a symbol resolver -- do we need this? can just pass 0? */
		//);

		core::iterator_df<> start_df(i_subp);
		unsigned subp_depth = start_df.depth();
		unsigned initial_depth = subp_depth;
		++start_df;
		
		/* This predicate decides whether we're interested in a particular local. */
		auto p = [](iterator_df<with_dynamic_location_die> i_dyn) {
			auto t = i_dyn->get_type();
			if (!t) return false;
			auto concrete_t = t->get_concrete_type();
			if (!concrete_t) return false;
			return concrete_t.is_a<core::pointer_type_die>();
		};
		
		/* Optimisation: don't bother exploring subtrees that are types, because they never 
		 * contain variables. */
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
			
			// enumerate the vaddr ranges of this DIE
			// -- note that some DIEs will be "for all vaddrs"
			// -- noting also that static variables need to be ignored
			
			// skip static variables
			if (i_bf.is_a<variable_die>() && i_bf.as_a<variable_die>()->has_static_storage())
			{
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
			
			// for each of this variable's intervals, add it to the map
			int interval_index = 0;
			for (auto i_locexpr = var_loclist.begin(); 
				i_locexpr != var_loclist.end(); ++i_locexpr)
			{
				std::set< pair<iterator_df<with_dynamic_location_die>, encap::loc_expr > > singleton_set;
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
				Dwarf_Unsigned cu_base = opt_cu_base->addr;
				
				// handle "for all vaddrs" entries
				boost::icl::discrete_interval<Dwarf_Off> our_interval;
				auto print_sp_expr = [&our_interval, &root, elf_machine]() {
					/* Last question. What's the stack pointer in terms of the 
					 * CFA? We can answer this question by faking up a location
					 * list referring to the stack pointer, and asking libdwarfpp
					 * to rewrite that.*/
					cerr << "Calculating rewritten-SP loclist..." << endl;
					auto sp_loclist = encap::rewrite_loclist_in_terms_of_cfa(
						encap::loclist(dwarf_stack_pointer_expr_for_elf_machine(
							elf_machine,
							our_interval.lower(), 
							our_interval.upper()
						)),
						root.get_frame_section(), 
						dwarf::spec::opt<const encap::loclist&>() /* opt_fbreg */
					);
					cerr << "Got SP loclist " << sp_loclist << endl;
				};
				if ((i_locexpr->lopc == 0 && 0 == i_locexpr->hipc)
					|| (i_locexpr->lopc == 0 && i_locexpr->hipc == std::numeric_limits<Dwarf_Off>::max()))
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
		
		/* Now account for the frame information. 
		 * We use the same interval map,
		 * *but* we use it to record ranges where a given callee-save register is saved. 
		 * NOTE that we're still going subprogram by subprogram.
		 * For each frame entry overlapping this subprogram,
		 * compute the set of callee-save registers it can recover (i.e. for the caller's frame).
		 * Then add a record to the intervals map,
		 * not saying "this local variable is stored at this CFA offset", but
		 *            "this register, of the caller, is stored at this CFA offset".
		 */
		
		/* We want to report discarded fps/locals once per subprogram.
		 * Keep an interval map of discarded items.
		 */
		retained_intervals_t frame_intervals;
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

				auto i_el = &i_el_pair->first;
				Dwarf_Addr addr_from_zero;
				
				/* Is this DIE interesting? Apply the predicate. */
				if (!p(*i_el))
				{
					//cerr << "Skipping uninteresting local: "
					//	<< *i_el 
					//	<< "in the vaddr range " 
					//	<< std::hex << i_int->first << std::dec
					//	<< endl;
					set< pair< iterator_df< with_dynamic_location_die >, string> > singleton_set;
					singleton_set.insert(make_pair(*i_el, string("not-interesting-local")));
					discarded_intervals += make_pair(i_int->first, singleton_set);
					continue;
				}
				
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
						<< std::hex << i_int->first << std::dec;
					set< pair< iterator_df< with_dynamic_location_die >, string> > singleton_set;
					singleton_set.insert(make_pair(*i_el, string("static-masquerading-as-local")));
					discarded_intervals += make_pair(i_int->first, singleton_set);
					continue;
				}
				
#ifndef NDEBUG
				auto count_intervals = [](const retained_intervals_t& f) -> unsigned {
					unsigned count = 0;
					for (auto i = f.begin(); i != f.end(); ++i, ++count);
					return count;
				};
				auto sanity_check_post = [count_intervals](const retained_intervals_t& f, unsigned previous_size) {
					unsigned count = count_intervals(f);
					if (count != f.size())
					{
						cerr << "Warning: count " << count << " != iterative size " << f.iterative_size() 
							<< " (previous size: " << previous_size << ")" 
							<< endl;
					}
					assert(count == f.iterative_size());
					/* Also sanity-check the member sets. */
					for (auto i = f.begin(); i != f.end(); ++i, ++count)
					{
						unsigned set_size = 0;
						for (auto i_s = i->second.begin(); i_s != i->second.end(); ++i_s, ++set_size)
						{

						}
						if (set_size != i->second.size())
						{
							cerr << "Warning: set iterative size " << set_size
								 << " != claimed size() " << i->second.size()
							<< endl;
						}
					}
				};
				#define SANITY_CHECK_PRE(f) /* do { unsigned count = count_intervals(f); \
					cerr << "Adding an interval (width " << (i.upper() - i.lower()) \
					    << " to a map of size " << f.size() << ", count " << count << endl; */ \
						do { for (auto i = f.begin(); i != f.end(); ++i) { \
							assert(sanity_check_set(i->second)); \
						} } while (0)
					
				#define SANITY_CHECK_POST(f) /* sanity_check_post(f, count); } while (0) */
#else
				#define SANITY_CHECK_PRE(f) do { 
				#define SANITY_CHECK_POST(f)  } while (0)
#endif
				
				/* Is the loclist just saying "in register X"? 
				 * If so, handle this first. */
				 if (i_el_pair->second.size() == 1
					&& i_el_pair->second.begin()->lr_atom >= DW_OP_reg0
					&& i_el_pair->second.begin()->lr_atom <= DW_OP_reg31)
				{
					int num = i_el_pair->second.begin()->lr_atom - DW_OP_reg0;
					cerr << "Found a simple register-located local/fp ("
						<< "register number " << num << ")"
						<< std::hex << i_int->first << std::dec
						<< ": "
						<< *i_el
						<< endl;
					set< retained_element > singleton_set;
					singleton_set.insert(retained_element(
						(const store_location&) make_pair(num, 0), *i_el
					));
					unsigned previous_size = frame_intervals.size();
					SANITY_CHECK_PRE(frame_intervals);
					frame_intervals += make_pair(i_int->first, singleton_set);
					SANITY_CHECK_POST(frame_intervals);
					continue;
				}
				else
				{
					try
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
						/* This probably means our variable/fp is in a register and not 
						 * in a stack location. That's fine. Warn and continue. */
						if (debug_out > 1)
						{
							cerr << "Warning: we think this is a complex register-located local/fp or pass-by-reference fp "
								<< "in the vaddr range " 
								<< std::hex << i_int->first << std::dec
								<< ": "
								<< *i_el;
						}
						set< pair< iterator_df< with_dynamic_location_die >, string> > singleton_set;
						singleton_set.insert(make_pair(*i_el, string("complex-register-located")));
						discarded_intervals += make_pair(i_int->first, singleton_set);
						continue;
					}
					catch (...)
					{
						cerr << "Warning: something strange happened when computing location for fp: " 
							<< *i_el;
						//discarded.push_back(make_pair(*i_el, "register-located"));
						set< pair< iterator_df< with_dynamic_location_die >, string> > singleton_set;
						singleton_set.insert(make_pair(*i_el, string("something-strange")));
						discarded_intervals += make_pair(i_int->first, singleton_set);
						continue;
					}
				}
				Dwarf_Signed frame_offset = static_cast<Dwarf_Signed>(addr_from_zero);
				// cerr << "Found on-stack location (fb + " << frame_offset << ") for fp/var " << *i_el 
				// 		<< "in the vaddr range " 
				// 		<< std::hex << i_int->first << std::dec << endl;

				/* We only add to by_frame_off if we have complete type => nonzero length. */
				if ((*i_el)->find_type() && (*i_el)->find_type()->get_concrete_type())
				{
					//by_frame_off[frame_offset] = *i_el;
					set< retained_element > singleton_set;
					singleton_set.insert(retained_element(store_location(-1, frame_offset), *i_el));
					unsigned previous_size = frame_intervals.size();
					SANITY_CHECK_PRE(frame_intervals);
					frame_intervals += make_pair(i_int->first, singleton_set);
					SANITY_CHECK_POST(frame_intervals);
				}
				else
				{
					set< pair< iterator_df< with_dynamic_location_die >, string> > singleton_set;
					singleton_set.insert(make_pair(*i_el, string("no concrete type")));
					discarded_intervals += make_pair(i_int->first, singleton_set);
				}
			}
		} /* end for i_int */
		
		/* Now merge the frame information. We expect one FDE for this subprogram,
		 * but we might conceivably have none or many. */
		for (auto i_i_fde = fdes_by_subprogram[i_subp].begin();
			i_i_fde != fdes_by_subprogram[i_subp].end();
			++i_i_fde)
		{
			auto i_fde = *i_i_fde;
			const Cie& cie = *i_fde->find_cie();
			Dwarf_Addr fde_lopc = i_fde->get_low_pc();
			Dwarf_Addr fde_hipc = i_fde->get_low_pc() + i_fde->get_func_length();

			cerr << "Processing FDE for range " << std::hex << fde_lopc << "-"
				<< fde_hipc << std::dec << "(subprogram ";
			if (i_subp.name_here()) cerr << *i_subp.name_here();
			else cerr << "0x" << std::hex << i_subp.offset_here() << std::dec;
			cerr << ")" << endl;

			/* decode the FDE */
			auto result = i_fde->decode();
			result.add_unfinished_row(i_fde->get_low_pc() + i_fde->get_func_length());
			
			// enumerate our columns
			set<int> all_columns;
			all_columns.insert(DW_FRAME_CFA_COL3);
			for (auto i_row = result.rows.begin(); i_row != result.rows.end(); ++i_row)
			{
				for (auto i_reg = i_row->second.begin(); i_reg != i_row->second.end(); ++i_reg)
				{
					all_columns.insert(i_reg->first);
				}
			}

			typedef std::function<void(int, optional< pair<int, FrameSection::register_def> >)>
			 visitor_function;
			
			auto p = [](int col) {
				return is_callee_save_register(col);
			};

			int ra_rule_number = cie.get_return_address_register_rule();
			auto visit_columns = [all_columns, ra_rule_number](
				 visitor_function visit, 
				 optional<const set< pair<int, FrameSection::register_def> > &> opt_i_row
				) {

				auto get_column = [&opt_i_row](int col) {

					if (!opt_i_row) return optional< pair<int, FrameSection::register_def> >();
					else
					{
						map<int, FrameSection::register_def> m(opt_i_row->begin(), opt_i_row->end());
						auto found = m.find(col);
						return found != m.end() ? make_pair(found->first, found->second) : optional< pair<int, FrameSection::register_def> >();
					}
				};

				// always visit CFA column
				visit(DW_FRAME_CFA_COL3, get_column(DW_FRAME_CFA_COL3));

				// visit other columns that exist, except the ra rule for now
				for (auto i_col = all_columns.begin(); i_col != all_columns.end(); ++i_col)
				{
					if (*i_col != DW_FRAME_CFA_COL3 && *i_col != ra_rule_number)
					{
						visit(*i_col, get_column(*i_col));
					}
				}

				// finally, always visit the ra rule 
				visit(ra_rule_number, get_column(ra_rule_number));
			};

			visitor_function row_column_visitor = [all_columns, ra_rule_number, &p, 
				fde_lopc, fde_hipc, &frame_intervals]
				(int col, optional< pair<int, FrameSection::register_def> > found_col)  -> void {

				if (!found_col || !p(col)) {} // s << std::left << "u" << std::right;
				else
				{
					switch (found_col->second.k)
					{
						case FrameSection::register_def::INDETERMINATE:
						case FrameSection::register_def::UNDEFINED: 
							break;

						case FrameSection::register_def::REGISTER: {
							// register "col" is saved in register "regnum"
							int regnum = found_col->second.register_plus_offset_r().first;
							std::set< retained_element > singleton_set;
							//singleton_set.insert(retained_element(col, store_location(regnum)));
							singleton_set.insert(retained_element(
								(const store_location&) make_pair(regnum, 0), col
							));
							SANITY_CHECK_PRE(frame_intervals);
							frame_intervals += make_pair(
								boost::icl::interval<Dwarf_Addr>::right_open(
									fde_lopc,
									fde_hipc
								),
								singleton_set
							);
							SANITY_CHECK_POST(frame_intervals);
						} break;

						case FrameSection::register_def::SAVED_AT_OFFSET_FROM_CFA: {
							int saved_offset = found_col->second.saved_at_offset_from_cfa_r();
							std::set< retained_element > singleton_set;
							//singleton_set.insert(saved_caller_register(col, make_pair(-1, saved_offset)));
							singleton_set.insert(retained_element(
								(const store_location&) make_pair(-1, saved_offset), col
							));
							SANITY_CHECK_PRE(frame_intervals);
							frame_intervals += make_pair(
								boost::icl::interval<Dwarf_Addr>::right_open(
									fde_lopc,
									fde_hipc
								),
								singleton_set
							);
							SANITY_CHECK_POST(frame_intervals);
						} break;
						case FrameSection::register_def::SAVED_AT_EXPR:
							// we can't represent this. :-(
							break;
						case FrameSection::register_def::VAL_IS_OFFSET_FROM_CFA:
						case FrameSection::register_def::VAL_OF_EXPR: 
						default:
							// FIXME: is it useful for us to have VAL_IS and VAL_OF?
							break;
					}
				}
			};

			// process the row contents
			for (auto i_int = result.rows.begin(); i_int != result.rows.end(); ++i_int)
			{
				visit_columns(row_column_visitor, i_int->second);
			}
		}
		
		cerr << "Finished processing FDEs for this subprogram." << endl;
		
		intervals_by_subprogram[i_subp] = frame_intervals;
		if (frame_intervals.size() == 0)
		{
			cerr << "Warning: no frame element intervals for subprogram " << i_subp << endl;
		}
		
		/* Now for each distinct interval in the frame_intervals map... */
		for (auto i_frame_int = frame_intervals.begin(); i_frame_int != frame_intervals.end();
			++i_frame_int)
		{
			/* Output in offset order, CHECKing that there is no overlap (sanity). */
			cout << "\n/* for stack frame ";
			string unmangled_typename = typename_for_vaddr_interval(i_subp, i_frame_int->first);
			
			string cu_name = *i_subp.enclosing_cu().name_here();
			
			cout << unmangled_typename
				 << " defined in " << cu_name << ", "
				 << "vaddr range " << std::hex << i_frame_int->first << std::dec << " */\n";
				 
			cout << "struct stored_ptrs " << ptrs_typename(make_pair(cu_name, unmangled_typename))
				<< " = {\n\t" 
				<< "0x" << std::hex << i_frame_int->first.lower() 
				<< ", 0x" << i_frame_int->first.upper() << std::dec << ",\n\t"
				<< i_frame_int->second.size() << " /* nstored */,\n\t"
				<< /* contained[] */ "/* stored */ {\n\t\t";
			unsigned set_iterative_size = 0;
			for (auto i_by_off = i_frame_int->second.begin(); // dummy to keep in scope for debugging
				i_by_off != i_frame_int->second.end(); ++i_by_off, ++set_iterative_size);
			auto set_copy = i_frame_int->second;
			cerr << "Frame retained element set has " << set_iterative_size << " items, size " 
				<< i_frame_int->second.size() << endl;
			unsigned copy_iterative_size = 0;
			for (auto i_by_off = set_copy.begin(); // dummy to keep in scope for debugging
				i_by_off != set_copy.end(); ++i_by_off, ++copy_iterative_size);
			cerr << "Copy of it has " << copy_iterative_size << " items, size " 
				<< set_copy.size() << endl;
			for (auto i_by_off = i_frame_int->second.begin(); i_by_off != i_frame_int->second.end(); ++i_by_off)
			{
				if (i_by_off != i_frame_int->second.begin()) cout << ",\n\t\t";
				/* begin the struct */
				cout << "{\n\t\t\t.what = ";
				/*
					{
						.what = CALLER_REG,
						.what_info = { caller_reg: { 0 /* rbx * / } },
						.where = STACK,
						.where_info = { stack: { -56 } }
					},
				*/
				// what
				if (i_by_off->is_local)
				{
					cout << "LOCAL,\n\t\t\t";
					cout << ".what_info = { local: { \"" 
						<< (i_by_off->local_die.name_here() 
							? *i_by_off->local_die.name_here() : "(anonymous)")
						<< "\" } },\n\t\t\t";
				}
				else
				{
					cout << "CALLER_REG,\n\t\t\t";
					cout << ".what_info = { caller_reg: { " 
						<< i_by_off->reg << " /* register " 
						<< dwarf_regnames_for_elf_machine(elf_machine)[i_by_off->reg]
						<< " */ } },\n\t\t\t";
				}
				
				if (i_by_off->loc.regnum() == -1)
				{
					cout << ".where = STACK,\n\t\t\t"
						 << ".where_info = { stack: { " << i_by_off->loc.cfa_offset() 
						 << " } }\n\t\t}";
				}
				else
				{
					cout << ".where = REG,\n\t\t\t"
						 << ".where_info = { reg: { " << i_by_off->loc.regnum() 
						 << " /* register " 
						 << dwarf_regnames_for_elf_machine(elf_machine)[i_by_off->loc.regnum()]
						 << " */ } }\n\t\t}";
				}
// 					string mangled_name = mangle_typename(canonical_key_for_type(i_by_off->local_die->find_type()));
// 					else
// 					{
// 						cout << "\"" << "register "
// 							<< dwarf_regnames_for_elf_machine(elf_machine)[i_by_off->loc.regnum()] << "\"";
// 					}
// 					cout << ", "
// 						 << "&" << mangled_name
// 						 << "}"
// 						 << " /* ";
// 					if (i_by_off->local_die.name_here()) cout << *i_by_off->local_die.name_here();
// 					else cout << "(anonymous)"; 
// 					cout << " -- " << i_by_off->local_die.spec_here().tag_lookup(
// 							i_by_off->local_die.tag_here())
// 						<< " @" << std::hex << i_by_off->local_die.offset_here() << std::dec;
// 					cout << " */ ";
// 				}
// 				else // saved register
// 				{
// 					assert(i_by_off->saved_reg.regnum() != -1);
// 					if (i_by_off->saved_reg.saved_location().regnum() == -1)
// 					{
// 						cout << i_by_off->saved_reg.saved_location().cfa_offset();
// 					}
// 					else
// 					{
// 						cout << "\"" << "register "
// 							<< dwarf_regnames_for_elf_machine(elf_machine)[
// 								i_by_off->saved_reg.saved_location().regnum()]
// 							<< "\"";
// 					}
// 					cout << ", ";
// 					cout << "(void*)0 /* saved caller reg -- word-sized but no fixed type */ "
// 						 << "}"
// 						 << " /* ";
// 					cout << "caller's saved " 
// 						<< dwarf_regnames_for_elf_machine(elf_machine)[i_by_off->saved_reg.regnum()]
// 						<< ")";
// 					cout << " */ ";
//				}
			}
			cout << "\n\t}";
			cout << "\n};\n";
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

	// success! 
	return 0;
}

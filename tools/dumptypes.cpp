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
#include <fileno.hpp>

#include "helpers.hpp"

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
using dwarf::core::with_dynamic_location_die;
using dwarf::core::address_holding_type_die;
using dwarf::core::array_type_die;
using dwarf::core::type_chain_die;

using dwarf::lib::Dwarf_Off;

// regex usings
using boost::regex;
using boost::regex_match;
using boost::smatch;
using boost::regex_constants::egrep;
using boost::match_default;
using boost::format_all;

// this encodes only the set of types, not the relations between them!
struct master_relation_t : public std::map< uniqued_name, iterator_df<type_die> >
{
	//using map::map;
	template<typename... Args>
	master_relation_t(Args&&... args): map(std::forward<Args>(args)...) {}
};

// we store *iterators* to avoid the inefficient iterator_here(), find() stuff
// BUT note that iterators are not totally ordered, so we can't store them 
// as keys in a set (without breaking the equality test). So we use a map
// keyed on their full source path. 
typedef std::map< pair<string, string>, iterator_sibs<core::subprogram_die> > subprograms_list_t;
typedef std::map< pair<string, string>, iterator_sibs<core::variable_die> > statics_list_t;

void print_stacktypes_output(const subprograms_list_t& l);
void print_statics_output(const statics_list_t& l);

static string typename_for_vaddr_interval(iterator_df<subprogram_die> i_subp, 
	const boost::icl::discrete_interval<Dwarf_Off> interval);

uniqued_name add_type(iterator_df<type_die> t, master_relation_t& r)
{
	if (t != t->get_concrete_type()) return make_pair("", ""); // only add concretes
	
	if (t == iterator_base::END) return make_pair("", "");
	
	/* If it's a base type, we might not have a decl_file, */
	if (!t->get_decl_file() || *t->get_decl_file() == 0)
	{
		if (t.tag_here() != DW_TAG_base_type
		 && t.tag_here() != DW_TAG_pointer_type
		 && t.tag_here() != DW_TAG_reference_type
		 && t.tag_here() != DW_TAG_rvalue_reference_type
		 && t.tag_here() != DW_TAG_array_type
		 && t.tag_here() != DW_TAG_subroutine_type)
		{
			cerr << "Warning: skipping non-base non-pointer non-array non-subroutine type described by " << *t //
			//if (t.name_here()) cerr << t.name_here();
			//else cerr << "(unknown, offset: " << std::hex << t.offset_here() << std::dec << ")";
			/*cerr */ << " because no file is recorded for its definition." << endl;
			return make_pair("", "");
		}
		// else it's a base type, so we go with the blank type
		// FIXME: should canonicalise base types here
		// (to the same as the ikind/fkinds come out from Cil.Pretty)
	}
	uniqued_name n = key_from_type(t);
	
	smatch m;
	if (r.find(n) != r.end()
		&& t.tag_here() != DW_TAG_base_type
		&& !regex_match(n.second, m, regex(".*__(PTR|REF|RR|ARR[0-9]+)_.*")))
	{
		cerr << "warning: non-base non-pointer non-array type named " << n.second << " already exists!" << endl;
	}
	r[n] = t;
	
// 	/* Now recurse on members */
// 	if (!t.is_a<with_data_members_die>()) return n;
// 	auto member_children = t.as_a<with_data_members_die>().children().subseq_of<member_die>();
// 	for (auto i_child = member_children.first;
// 		i_child != member_children.second; ++i_child)
// 	{
// 		// skip "declared", "external" members, i.e. static member vars
// 		if (i_child->get_declaration() && *i_child->get_declaration()
// 		 && i_child->get_external() && *i_child->get_external())
// 		{
// 			continue;
// 		}
// 		
// 		assert(i_child->get_type() != iterator_base::END);
// 		if (i_child->get_type()->get_concrete_type() == t) 
// 		{
// 			cout << "Found directly recursive data type: "
// 				<< t
// 				<< " contains member "
// 				<< i_child.base().base()
// 				<< " of type "
// 				<< i_child->get_type()->get_concrete_type()
// 				<< " which equals " 
// 				<< t
// 				<< endl;
// 			assert(false);
// 		}
// 		recursively_add_type(i_child->get_type(), r);
// 	}
	
	return n;
}

static string fq_pathname(const string& dir, const string& path)
{
	if (path.length() > 0 && path.at(0) == '/') return path;
	else return dir + "/" + path;
}

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
	struct sticky_root_die : public root_die
	{
		using root_die::root_die;
		
		// virtual bool is_sticky(const core::abstract_die& d) { return true; }
		
	} root(fileno(infstream));
	assert(&root.get_frame_section());
	opt<core::root_die&> opt_r = root; // for debugging
	master_relation_t master_relation;

	struct subprogram_key : public pair< pair<string, string>, string > // ordering for free
	{
		subprogram_key(const string& subprogram_name, const string& sourcefile_name, 
			const string& comp_dir) : pair(make_pair(subprogram_name, sourcefile_name), comp_dir) {}
		string subprogram_name() const { return first.first; }
		string sourcefile_name() const { return first.second; }
		string comp_dir() const { return second; }
	};

	map<subprogram_key, iterator_df<subprogram_die> > subprograms_list;
	lib::Dwarf_Off previous_offset = 0UL;
	for (iterator_df<> i = root.begin(); i != root.end(); ++i)
	{
		assert(i.offset_here() >= previous_offset); // == for initial case, > afterwards
		if (i.is_a<type_die>())
		{
			// add it to the relation
			opt<string> opt_name = i.name_here(); // for debugging
			if (opt_name)
			{
				string name = *opt_name;
				assert(name != "");
				if (name == "abstract_def")
				{
					assert(true); // for debugging
				}
			}
			add_type(i.as_a<type_die>(), master_relation);
		}
		previous_offset = i.offset_here();
	}
	cerr << "Master relation contains " << master_relation.size() << " data types." << endl;
	/* For each type we output a record:
	 * - a pointer to its name;
	 * - a length prefix;
	 * - a list of <offset, included-type-record ptr> pairs.
	 */

	cout << "struct rec \n\
{ \n\
	const char *name; \n\
	short pos_maxoff; \n\
	short neg_maxoff; \n\
	unsigned nmemb:12;         // 12 bits -- number of `contained's\n\
	unsigned is_array:1;       // 1 bit\n\
	unsigned array_len:19;\n\
	struct { \n\
		signed offset; \n\
		struct rec *ptr; \n\
	} contained[]; \n\
};\n";
	/* DWARF doesn't reify void, but we do. So output a rec for void first of all. */
	cout << "\n/* uniqtype for void */\n";
	cout << "\n__asm__(\".pushsection .__uniqtype__void, \\\"awG\\\", @progbits, __uniqtype__void, comdat\"); \n";
	cout << "struct rec " << mangle_typename(make_pair(string(""), string("void")))
		<< " = {\n\t\"" << "void" << "\",\n\t"
		<< "0" << " /* pos_maxoff (void) */,\n\t"
		<< "0" << " /* neg_maxoff (void) */,\n\t"
		<< "0" << " /* nmemb (void) */,\n\t"
		<< "0" << " /* is_array (void) */,\n\t"
		<< "0" << " /* array_len (void) */,\n\t"
		<< "/* contained */ { }\n};\n";
	cout << "\n__asm__(\".popsection\"); \n";

	// write a forward declaration for every uniqtype we need
	set<string> names_emitted;
	map<string, set< iterator_df<type_die> > > types_by_name;
	for (auto i_pair = master_relation.begin(); i_pair != master_relation.end(); ++i_pair)
	{
		string s = mangle_typename(i_pair->first);
		names_emitted.insert(s);
		types_by_name[i_pair->first.second].insert(i_pair->second);
		cout << "extern struct rec " << s << ";" << endl;
	}

	for (auto i_vert = master_relation.begin(); i_vert != master_relation.end(); ++i_vert)
	{
		auto opt_sz = i_vert->second->calculate_byte_size();
		if (!opt_sz)
		{
			// we have an incomplete type
			cerr << "Warning: type " 
				<< i_vert->first.second
				<< " is incomplete, treated as zero-size." << endl;
		}
		if (i_vert->first.second == string("void"))
		{
			cerr << "Warning: skipping explicitly declared void type from CU "
				<< *i_vert->second.enclosing_cu().name_here()
				<< endl;
			continue;
		}
		
		cout << "\n/* uniqtype for " << i_vert->first.second 
			<< " defined in " << i_vert->first.first << " */\n";
		auto members = i_vert->second.children().subseq_of<member_die>();
		std::vector< iterator_base > real_members;
		std::vector< Dwarf_Unsigned > real_member_offsets;
		for (auto i_edge = members.first; i_edge != members.second; ++i_edge)
		{
			/* if we don't have a byte offset, skip it */
			opt<Dwarf_Unsigned> opt_offset = i_edge->byte_offset_in_enclosing_type(root);
			if (!opt_offset) continue;
			else
			{ 
				real_members.push_back(i_edge.base().base()); 
				real_member_offsets.push_back(*opt_offset);
			}
		}		
		unsigned members_count = real_members.size();
		unsigned array_len;
		if  (i_vert->second.is_a<array_type_die>())
		{
			auto opt_array_len = i_vert->second.as_a<array_type_die>()->element_count(root);
			if (opt_array_len) array_len = *opt_array_len;
			else array_len = 0;
		} else array_len = 0;
		string mangled_name = mangle_typename(i_vert->first);
		cout << "\n__asm__(\".pushsection ." << mangled_name << ", \\\"awG\\\", @progbits, " << mangled_name << ", comdat\"); \n";
		cout << "struct rec " << mangle_typename(i_vert->first)
			<< " = {\n\t\"" << i_vert->first.second << "\",\n\t"
			<< (opt_sz ? *opt_sz : 0) << " /* pos_maxoff " << (opt_sz ? "" : "(incomplete) ") << "*/,\n\t"
			<< "0 /* neg_maxoff */,\n\t"
			<< (i_vert->second.is_a<array_type_die>() ? 1 : members_count) << " /* nmemb */,\n\t"
			<< (i_vert->second.is_a<array_type_die>() ? "1" : "0") << " /* is_array */,\n\t"
			<< array_len << " /* array_len */,\n\t"
			<< /* contained[0] */ "/* contained */ {\n\t\t";

		if (i_vert->second.is_a<array_type_die>())
		{
			// array: write a single entry, for the element type
			/* begin the struct */
			cout << "{ ";

			// compute offset

			cout << "0, ";

			// compute and print destination name
			auto k = key_from_type(i_vert->second.as_a<array_type_die>()->get_type());
			/* FIXME: do multidimensional arrays get handled okay like this? 
			 * I reckon so, but am not yet sure. */
			string mangled_name = mangle_typename(k);
			cout << "&" << mangled_name;

			// end the struct
			cout << " }";
		}
		else // non-array -- use real members
		{
			unsigned i_membernum = 0;
			std::set<lib::Dwarf_Unsigned> used_offsets;
			opt<iterator_base> first_with_byte_offset;
			auto i_off = real_member_offsets.begin();
			for (auto i_i_edge = real_members.begin(); i_i_edge != real_members.end(); ++i_i_edge, ++i_membernum, ++i_off)
			{
				auto i_edge = i_i_edge->as_a<member_die>();

				/* if we're not the first, write a comma */
				if (i_i_edge != real_members.begin()) cout << ",\n\t\t";

				/* begin the struct */
				cout << "{ ";

				// compute offset

				cout << *i_off << ", ";

				// compute and print destination name
				auto k = key_from_type(i_edge->get_type());
				string mangled_name = mangle_typename(k);
				if (names_emitted.find(mangled_name) == names_emitted.end())
				{
					cout << "Type " << i_edge->get_type()
						<< ", concretely " << i_edge->get_type()->get_concrete_type()
						<< " was not emitted previously." << endl;
					for (auto i_name = names_emitted.begin(); i_name != names_emitted.end(); ++i_name)
					{
						if (i_name->substr(i_name->length() - k.second.length()) == k.second)
						{
							cout << "Possible near-miss: " << *i_name << endl;
						}
					}
					assert(false);
				}
				cout << "&" << mangled_name;

				// end the struct
				cout << " }";
			}
		}
		
		cout << "\n\t}"; /* end contained */
		cout << "\n};\n"; /* end struct rec */
		cout << "\n__asm__(\".popsection\"); \n";
	}
	
	/* Now create linker aliases for any that were unique. */
	cout << "/* Begin aliases. */" << endl;
	for (auto i_by_name_pair = types_by_name.begin(); i_by_name_pair != types_by_name.end();
		++i_by_name_pair)
	{
		if (i_by_name_pair->second.size() == 1)
		{
			auto full_name_pair = key_from_type(*i_by_name_pair->second.begin());
			string full_name = mangle_typename(full_name_pair);
			pair<string, string> abbrev_name_pair = make_pair("", full_name_pair.second);
			string abbrev_name = mangle_typename(abbrev_name_pair);
			cout << "extern struct rec " << abbrev_name << " __attribute__((alias(\""
				<< cxxgen::escape(full_name) << "\")));" << endl;
		}
		else
		{
			cout << "/* Not aliasing " << i_by_name_pair->first << "; set is {\n";
			for (auto i_t = i_by_name_pair->second.begin(); i_t != i_by_name_pair->second.end(); ++i_t)
			{
				if (i_t != i_by_name_pair->second.begin()) cout << ",\n";
				cout << "\t" << mangle_typename(key_from_type(*i_t)) << endl;
			}
			
			cout << "} */" << endl;
		}
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
	using dwarf::lib::Dwarf_Off;
	using dwarf::lib::Dwarf_Addr;
	using dwarf::lib::Dwarf_Signed;
	using dwarf::lib::Dwarf_Unsigned;
	
	typedef std::set< pair< iterator_df<with_dynamic_location_die>, encap::loc_expr > > live_set_t;
	typedef boost::icl::interval_map< Dwarf_Off, live_set_t > intervals_t;
	typedef boost::icl::interval_map< 
			Dwarf_Off, 
			std::set< 
				pair<
					Dwarf_Signed, 
					iterator_df<with_dynamic_location_die> 
				> 
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
		
	map< iterator_df<subprogram_die>, retained_intervals_t > intervals_by_subprogram;
	
	for (auto i_i_subp = subprograms_list.begin(); i_i_subp != subprograms_list.end(); ++i_i_subp)
	{
		auto i_subp = i_i_subp->second;
		
		intervals_t subp_vaddr_intervals; // CU- or file-relative?

		/* Put this subp's vaddr ranges into the map */
		auto subp_intervals = i_subp->file_relative_intervals(
			root, 
			nullptr, nullptr /* FIXME: write a symbol resolver -- do we need this? can just pass 0? */
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
			cerr << "Saw loclist " << var_loclist << endl;
			var_loclist = encap::rewrite_loclist_in_terms_of_cfa(
				var_loclist, 
				root.get_frame_section(), 
				dwarf::spec::opt<const encap::loclist&>() /* opt_fbreg */
			);
			cerr << "Rewrote to loclist " << var_loclist << endl;
			
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
				
				auto opt_cu_base = i_subp.enclosing_cu()->get_low_pc();
				Dwarf_Unsigned cu_base = opt_cu_base->addr;
				
				// handle "for all vaddrs" entries
				boost::icl::discrete_interval<Dwarf_Off> our_interval;
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
						our_interval = boost::icl::interval<Dwarf_Off>::right_open(
							i_subp_int->first.lower() + cu_base,
							i_subp_int->first.upper() + cu_base
						);
						
						cerr << "Borrowing vaddr ranges of " << *i_subp
							<< " for dynamic-location " << *i_dyn;
						
						/* assert sane interval */
						assert(our_interval.lower() < our_interval.upper());
						/* assert sane size -- no bigger than biggest sane function */
						assert(our_interval.upper() - our_interval.lower() < 1024*1024);
						subp_vaddr_intervals += make_pair(
							our_interval,
							singleton_set
						); 
					}
					/* There should be only one entry in the location list if so. */
					assert(i_locexpr == var_loclist.begin());
					assert(i_locexpr + 1 == var_loclist.end());
				}
				else /* we have nonzero lopc and/or hipc */
				{
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
						<< std::hex << i_int->first << std::dec;
					set< pair< iterator_df< with_dynamic_location_die >, string> > singleton_set;
					singleton_set.insert(make_pair(*i_el, string("static-masquerading-as-local")));
					discarded_intervals += make_pair(i_int->first, singleton_set);
					continue;
				}
				
				try
				{
					std::stack<Dwarf_Unsigned> initial_stack; 
					initial_stack.push(0); 
					// call the evaluator directly
					// -- push zero (a.k.a. the frame base) onto the initial stack
					lib::evaluator e(i_el_pair->second,
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
						cerr << "Warning: we think this is a register-located local/fp or pass-by-reference fp "
							<< "in the vaddr range " 
							<< std::hex << i_int->first << std::dec
							<< ": "
					 		<< *i_el;
					}
					//discarded.push_back(make_pair(*i_el, "register-located"));
					set< pair< iterator_df< with_dynamic_location_die >, string> > singleton_set;
					singleton_set.insert(make_pair(*i_el, string("register-located")));
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
				Dwarf_Signed frame_offset = static_cast<Dwarf_Signed>(addr_from_zero);
				cerr << "Found on-stack location (fb + " << frame_offset << ") for fp/var " << *i_el 
						<< "in the vaddr range " 
						<< std::hex << i_int->first << std::dec << endl;

				/* We only add to by_frame_off if we have complete type => nonzero length. */
				if ((*i_el)->find_type() && (*i_el)->find_type()->get_concrete_type())
				{
					//by_frame_off[frame_offset] = *i_el;
					set< pair<Dwarf_Signed, iterator_df<with_dynamic_location_die> > > singleton_set;
					singleton_set.insert(make_pair(frame_offset, *i_el));
					frame_intervals += make_pair(i_int->first, singleton_set);
				}
				else
				{
					set< pair< iterator_df< with_dynamic_location_die >, string> > singleton_set;
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
		
		/* Now for each distinct interval in the frame_intervals map... */
		for (auto i_frame_int = frame_intervals.begin(); i_frame_int != frame_intervals.end();
			++i_frame_int)
		{
			unsigned frame_maxoff;
			signed frame_minoff;
			//if (by_frame_off.begin() == by_frame_off.end()) frame_size = 0;
			if (i_frame_int->second.size() == 0) { frame_maxoff = 0; frame_minoff = 0; }
			else
			{
				{
					auto i_maxoff_el = i_frame_int->second.end(); --i_maxoff_el;
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
					signed frame_max_offset = i_maxoff_el->first + calculated_maxel_size;
					frame_maxoff = (frame_max_offset < 0) ? 0 : frame_max_offset;
				}
				{
					auto i_minoff_el = i_frame_int->second.begin();
					signed frame_min_offset = i_minoff_el->first;
					frame_minoff = (frame_min_offset > 0) ? 0 : frame_min_offset;
				}
			}
			
			/* Output in offset order, CHECKing that there is no overlap (sanity). */
			cout << "\n/* uniqtype for stack frame ";
			string unmangled_typename = typename_for_vaddr_interval(i_subp, i_frame_int->first);
			
			string cu_name = *i_subp.enclosing_cu().name_here();
			
			cout << unmangled_typename
				 << " defined in " << cu_name << ", "
				 << "vaddr range " << std::hex << i_frame_int->first << std::dec << " */\n";
				 
			cout << "struct rec " << mangle_typename(make_pair(cu_name, unmangled_typename))
				<< " = {\n\t\"" << unmangled_typename << "\",\n\t"
				<< frame_maxoff << " /* pos_maxoff */,\n\t"
				<< frame_minoff << " /* neg_maxoff */,\n\t"
				<< i_frame_int->second.size() << " /* nmemb */,\n\t"
				<< "0 /* is_array */,\n\t"
				<< "0 /* array_len */,\n\t"
				<< /* contained[0] */ "/* contained */ {\n\t\t";
			for (auto i_by_off = i_frame_int->second.begin(); i_by_off != i_frame_int->second.end(); ++i_by_off)
			{
				if (i_by_off != i_frame_int->second.begin()) cout << ",\n\t\t";
				/* begin the struct */
				cout << "{ ";
				string mangled_name = mangle_typename(key_from_type(i_by_off->second->find_type()));
				assert(names_emitted.find(mangled_name) != names_emitted.end());
				cout << i_by_off->first << ", "
					<< "&" << mangled_name
					<< "}";
				cout << " /* ";
				if (i_by_off->second.name_here())
				{
					cout << *i_by_off->second.name_here();
				}
				else cout << "(anonymous)"; 
				cout << " -- " << i_by_off->second.spec_here().tag_lookup(
						i_by_off->second.tag_here())
					<< " @" << std::hex << i_by_off->second.offset_here() << std::dec;
				cout << " */ ";
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
	
	/* Now write frame_vaddr allocsites. */
	cout << "struct allocsite_entry\n\
{ \n\
	void *next; \n\
	void *prev; \n\
	void *allocsite; \n\
	struct rec *uniqtype; \n\
};\n";
	cout << "struct allocsite_entry frame_vaddrs[] = {" << endl;

	unsigned total_emitted = 0;
	// reminder: retained_intervals_t is
	// boost::icl::interval_map< 
	//		Dwarf_Off, 
	//		std::set< 
	//			pair<
	//				Dwarf_Signed, 
	//				iterator_df<with_dynamic_location_die> 
	//			> 
	//		>
	//	>
	
	/* NOTE: our allocsite chaining trick in libcrunch requires that our allocsites 
	 * are sorted in vaddr order, so that adjacent allocsites in the memtable buckets
	 * are adjacent in the table. So we sort them here. */
	set< pair< boost::icl::discrete_interval<Dwarf_Addr>, iterator_df<subprogram_die> > > sorted_intervals;
	for (map< iterator_df<subprogram_die>, retained_intervals_t >::iterator i_subp_intervals 
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
		cout << "\n\t/* frame alloc record for vaddr 0x" << std::hex << i_pair->first.lower() 
			<< "+" << i_pair->first.upper() << std::dec << " */";
		cout << "\n\t{ (void*)0, (void*)0, "
			<< "(char*) " << "0" // will fix up at load time
			<< " + " << i_pair->first.lower() << "UL, " 
			<< "&" << mangle_typename(make_pair(*i_pair->second.enclosing_cu().name_here(),
				typename_for_vaddr_interval(i_pair->second, i_pair->first)))
			<< " }";
		cout << ",";
		++total_emitted;
	}
	// output a null terminator entry
	cout << "\n\t{ (void*)0, (void*)0, (void*)0, (struct rec *)0 }";
	
	// close the list
	cout << "\n};\n";

	/* Now write static allocsites. As above, we also have to sort them. */
	set<pair< Dwarf_Addr, iterator_df<variable_die> > > sorted_statics;

	for (auto i = root.begin(); i != root.end(); ++i)
	{
		if (i.tag_here() == DW_TAG_variable
			&& i.has_attribute_here(DW_AT_location)
			&& i.as_a<variable_die>()->has_static_storage(root))
		{
			iterator_df<variable_die> i_var = i.as_a<variable_die>();
			boost::icl::interval_map<Dwarf_Addr, Dwarf_Unsigned> intervals;
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
			if (intervals.size() == 0)
			{
				// this happens if we don't have a real location -- continue
				continue;
			}
			
			// calculate its file-relative addr
			Dwarf_Off addr = intervals.begin()->first.lower();
			
			sorted_statics.insert(make_pair(addr, i_var));
		}
	}
	
	cout << "struct allocsite_entry statics[] = {" << endl;
	
	for (auto i_var_pair = sorted_statics.begin(); i_var_pair != sorted_statics.end(); ++i_var_pair)
	{
		auto addr = i_var_pair->first;
		auto& i_var = i_var_pair->second;

		ostringstream anon_name; anon_name << "0x" << std::hex << i_var.offset_here();

		cout << "\n\t/* static alloc record for object "
			 << (i_var.name_here() ? *i_var.name_here() : ("anonymous, DIE " + anon_name.str())) 
			 << " at vaddr " << std::hex << "0x" << addr << std::dec << " */";
		cout << "\n\t{ (void*)0, (void*)0, "
			<< "(char*) " << "0" // will fix up at load time
			<< " + " << addr << "UL, " 
			<< "&" << mangle_typename(key_from_type(i_var->find_type()))
			<< " }";
		cout << ",";
	}

	// output a null terminator entry
	cout << "\n\t{ (void*)0, (void*)0, (void*)0, (struct rec *)0 }";
	
	// close the list
	cout << "\n};\n";


	// success! 
	return 0;
}

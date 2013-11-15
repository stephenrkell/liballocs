/* This is a simple dwarfpp program which generates a C file
 * recording data on a uniqued set of data types  allocated in a given executable.
 */
 
#include <fstream>
#include <sstream>
#include <map>
#include <set>
#include <string>
#include <cctype>
#include <memory>
#include <boost/regex.hpp>
// #include <regex> // broken in GNU libstdc++!
//#include <boost/filesystem.hpp>
#include <boost/graph/graph_traits.hpp>
#include <boost/graph/graph_concepts.hpp>
#include <boost/graph/topological_sort.hpp>
#include <boost/graph/adjacency_list.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/icl/interval_map.hpp>
#include <srk31/algorithm.hpp>
#include <srk31/ordinal.hpp>
#include <dwarfpp/spec_adt.hpp>
#include <dwarfpp/adt.hpp>
#include <dwarfpp/cxx_compiler.hpp>
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
using std::shared_ptr;
using std::ostringstream;
using std::set;
using namespace dwarf;
//using boost::filesystem::path;
using dwarf::spec::compile_unit_die;
using dwarf::spec::type_die;
using dwarf::spec::with_data_members_die;
using dwarf::spec::with_dynamic_location_die;
using dwarf::spec::type_chain_die;
using dwarf::tool::cxx_compiler;

// regex usings
using boost::regex;
using boost::regex_match;
using boost::smatch;
using boost::regex_constants::egrep;
using boost::match_default;
using boost::format_all;

// this encodes only the uniqued set of types, not the relations between them!
//typedef std::map< uniqued_name, std::shared_ptr< spec::type_die > > master_relation_t;
struct master_relation_t : public std::map< uniqued_name, std::shared_ptr< spec::type_die > >
{
	//using map::map;
	template<typename... Args>
	master_relation_t(Args&&... args): map(std::forward<Args>(args)...) {}
};

typedef std::map< pair< string, unsigned long >, uniqued_name > allocsites_relation_t;
// we store *iterators* to avoid the inefficient iterator_here(), find() stuff
// BUT note that iterators are not totally ordered, so we can't store them 
// as keys in a set (without breaking the equality test). So we use a map
// keyed on their full source path. 
typedef std::map< pair<string, string>, core::iterator_sibs<core::subprogram_die> > subprograms_list_t;
typedef std::map< pair<string, string>, core::iterator_sibs<core::variable_die> > statics_list_t;

master_relation_t::key_type
key_from_type(shared_ptr<type_die> t);

/* To make sure argument-dependent lookup works properly for our 
 * vertex and edge descriptors, we define these as distinct data
 * types in the same namespace as our graph. */
typedef pair< pair<string, string> , master_relation_t::mapped_type> vertex_descriptor_raw_t;
struct vertex_descriptor_t 
: public vertex_descriptor_raw_t
  // i.e. master_relation_t::value_type without the const K
{
	//using pair::pair;
	template<typename... Args>
	vertex_descriptor_t(Args&&... args): vertex_descriptor_raw_t(std::forward<Args>(args)...) {}
};

static const vertex_descriptor_raw_t null_vertex(make_pair("", ""), shared_ptr<spec::type_die>());

struct edge_descriptor_t
: public shared_ptr<dwarf::spec::member_die>
{
	template<typename... Args>
	edge_descriptor_t(Args&&... args): shared_ptr(std::forward<Args>(args)...) {}
};

namespace boost 
{
	// specialise the boost graph_traits class for encap::dieset
	template <>
	struct graph_traits<master_relation_t> {
		typedef ::vertex_descriptor_t vertex_descriptor;
		typedef vertex_descriptor nonconst_vertex_descriptor;
		
		/* null_vertex() must return a thing exactly of the type 
		 * *vertex_iterator will return. Since we use a map
		 * iterator for that, we use the map value type here. 
		 * ::null_vertex will get usual-conversion'd to remove its 
		 * constness. */
		typedef master_relation_t::value_type null_vertex_t;
		static null_vertex_t null_vertex() {
			return ::null_vertex;
		}

		typedef ::edge_descriptor_t edge_descriptor;
		//typedef std::shared_ptr<dwarf::spec::member_die> edge_descriptor;
		
		/* To iterate through out-edges, we just do the usual member children
		 * iterator. */
		typedef dwarf::spec::with_data_members_die::member_iterator out_edge_iterator;

		/* To iterate through vertices, we just iterate through the map. */
		typedef master_relation_t::const_iterator vertex_iterator;
		
		typedef directed_tag directed_category;
		typedef allow_parallel_edge_tag edge_parallel_category;

		struct traversal_tag :
		  public virtual vertex_list_graph_tag,
		  public virtual incidence_graph_tag { };
		typedef traversal_tag traversal_category;
		
		typedef unsigned vertices_size_type;
		typedef unsigned edges_size_type;
		typedef unsigned degree_size_type;
	};
} /* end namespace boost */


/* Overloads go *outside* the boost namespace, to be found by ADL? */
namespace boost {
	boost::graph_traits<master_relation_t>::vertex_descriptor
	source(
		boost::graph_traits<master_relation_t>::edge_descriptor e,
		const master_relation_t& g
	)
	{
		// edge descriptor is a shared_ptr<member_die>
		// so we just look up the *containing* type's uniqued-name in the graph
		auto raw_parent = e->get_parent();
		assert(raw_parent);
		auto parent = dynamic_pointer_cast<with_data_members_die>(raw_parent);
		assert(parent);
		auto enclosing_cu = e->enclosing_compile_unit();
		assert(enclosing_cu);
		auto parent_type = dynamic_pointer_cast<type_die>(parent);
		assert(parent_type);
		auto uniqued_name = key_from_type(parent_type);
		
		auto found = g.find(uniqued_name);
		assert(found != g.end());
		return *found;
	}

	boost::graph_traits<master_relation_t>::vertex_descriptor
	target(
		boost::graph_traits<master_relation_t>::edge_descriptor e,
		const master_relation_t& g
	)
	{
		// edge descriptor is a shared_ptr<member_die>
		// so we just look up the *contained* type's uniqued-name in the graph
		auto t = e->get_type();
		assert(t);
		auto concrete_t = t->get_concrete_type();
		assert(concrete_t);
		auto enclosing_cu = concrete_t->enclosing_compile_unit();
		assert(enclosing_cu);
		auto uniqued_name = key_from_type(concrete_t);
		
		auto found = g.find(uniqued_name);
		assert(found != g.end());
		return *found;
	}

	inline std::pair<
		boost::graph_traits<master_relation_t>::out_edge_iterator,
		boost::graph_traits<master_relation_t>::out_edge_iterator >  
	out_edges(
		boost::graph_traits<master_relation_t>::vertex_descriptor u, 
		const master_relation_t& g)
	{
		/* If we're a with_data_members die, out edges are the
		 * member children. Otherwise, our out edges are empty. */
		auto with_data_members = dynamic_pointer_cast<with_data_members_die>(u.second);
		if (with_data_members)
 		{
			return make_pair(
				with_data_members->member_children_begin(),
				with_data_members->member_children_end()
			);
		}
		else
		{
			auto member_children_end = with_data_members_die::member_iterator(
				with_data_members_die::member_transform_iterator(
					with_data_members_die::member_filter_iterator(
						u.second->children_end(), 
						u.second->children_end()
					), std::dynamic_pointer_cast<spec::member_die, spec::basic_die>
					//std::function<
					//	std::shared_ptr<spec::member_die>(std::shared_ptr<spec::basic_die>)
					//>(&std::dynamic_pointer_cast<spec::member_die, spec::basic_die>)
				)
			);

			return make_pair(
				member_children_end,
				member_children_end
			);
		}
	}
	
	inline boost::graph_traits<master_relation_t>::degree_size_type
	out_degree(
		boost::graph_traits<master_relation_t>::vertex_descriptor u,
		const master_relation_t& g)
	{
		/* If we're a with_data_members die, out edge count is the
		 * count of member children. Otherwise, it's zero. */
		auto with_data_members = dynamic_pointer_cast<with_data_members_die>(u.second);
		if (with_data_members)
		{
			auto seq = out_edges(u, g);
			return srk31::count(seq.first, seq.second);
		}
		else
		{
			return 0;
		}
	}
}	
namespace boost {
	inline std::pair<
		boost::graph_traits<master_relation_t>::vertex_iterator,
		boost::graph_traits<master_relation_t>::vertex_iterator >  
	vertices(const master_relation_t& g)
	{
		return make_pair(g.begin(), g.end());
	}	

	inline boost::graph_traits<master_relation_t>::vertices_size_type 
	num_vertices(const master_relation_t& g)
	{
		return g.size();
	}
	
}

using boost::vertices;
using boost::num_vertices;
using boost::source;
using boost::target;
using boost::out_degree;
using boost::out_edges;

typedef std::vector<
	boost::graph_traits<master_relation_t>::nonconst_vertex_descriptor
> container;

void print_uniqtypes_output(const master_relation_t& g, const container& c);
void print_stacktypes_output(const subprograms_list_t& l);
void print_statics_output(const statics_list_t& l);
void print_allocsites_output(const allocsites_relation_t& r);

master_relation_t::key_type
key_from_type(shared_ptr<type_die> t)
{
	uniqued_name n;
	t = t->get_concrete_type();
	if (t->get_tag() != DW_TAG_pointer_type)
	{
		auto cu = t->enclosing_compile_unit();

		string file_to_use = (t->get_decl_file() && *t->get_decl_file() != 0) 
		                                     ? cu->source_file_name(*t->get_decl_file()) : "";
		
		// for named base types, we use equivalence classes
		string name_to_use; 
		if (!t->get_name() || t->get_tag() != DW_TAG_base_type)
		{
			name_to_use = t->get_name() ? *t->get_name() : offset_to_string(t->get_offset());
		}
		else // t->get_name() && t->get_tag == DW_TAG_base_type
		{
			string name_to_search_for = *t->get_name();
			// search equiv classes for a type of this name
			for (const char ***p_equiv = &cxx_compiler::base_typename_equivs[0]; *p_equiv != NULL; ++p_equiv)
			{
				for (const char **p_el = p_equiv[0]; *p_el != NULL; ++p_el)
				{
					if (name_to_search_for == string(*p_el))
					{
						name_to_use = (*p_equiv)[0];
						break;
					}
				}
				if (name_to_use != "") break; // we've got it
			}
			
			// if we've still not got it....
			if (name_to_use == "") name_to_use = name_to_search_for;
		}

		assert(name_to_use != "char"); // ... for example. It should be "signed char" of course! since cxx_compiler.cpp puts that one first
		n = make_pair(file_to_use, name_to_use);
	}
	else // DW_TAG_pointer_type
	{
		shared_ptr<type_die> opt_target_type = dynamic_pointer_cast<spec::pointer_type_die>(t)->get_type();
		if (opt_target_type) opt_target_type = opt_target_type->get_concrete_type();
		string opt_target_type_name;
		if (!opt_target_type) opt_target_type_name = "void";
		else
		{
			opt_target_type_name = opt_target_type->get_name() ? 
				*opt_target_type->get_name() 
			: offset_to_string(opt_target_type->get_offset());
		}
		/* We roll with: no header file, and the name with __PTR_ for '^'/
		 * OR, HMM, the header file of the ultimate pointee? YES, it should be this.
		 * Let's do it. */
		int levels_of_indirection = 0;
		shared_ptr<type_die> ultimate_pointee_type = t->get_concrete_type();
		shared_ptr<type_chain_die> type_chain;
		do
		{
			type_chain = dynamic_pointer_cast<type_chain_die>(ultimate_pointee_type);
			if (type_chain) 
			{
				++levels_of_indirection;
				ultimate_pointee_type = type_chain->get_type();
				if (ultimate_pointee_type) ultimate_pointee_type = ultimate_pointee_type->get_concrete_type();
			}
		} while (type_chain);
		
		assert(levels_of_indirection >= 1);
		
		string defining_header;
		if (!ultimate_pointee_type)
		{
			// we have the "void" type, possibly indirected over multiple levels
			defining_header = "";
		}
		else 
		{
			defining_header = 
			(ultimate_pointee_type->get_decl_file() && *ultimate_pointee_type->get_decl_file() != 0) 
			   ? ultimate_pointee_type->enclosing_compile_unit()->source_file_name(
			      *ultimate_pointee_type->get_decl_file()) 
			   : "";
		}

		string target_typename_to_use = opt_target_type ? key_from_type(opt_target_type).second : "void";
		
		ostringstream os(std::ios::out | std::ios::binary);
		std::ostream_iterator<char, char> oi(os);
		
		// here we are translating a dumpallocs-style type descriptor name...
		// ... into a uniqtypes-style name. BUT WHY? 
		//regex_replace(oi, s.begin(), s.end(),
		//	regex("(\\^)"), "(__PTR_)", 
		//	match_default | format_all);
		//assert(os.str() != "char"); // ... for example
		
		for (int i = 0; i < levels_of_indirection; ++i)
		{
			os << "__PTR_";
		}
		os << target_typename_to_use;
		
		n = make_pair(defining_header, os.str());
	}
	
	return n;
}

shared_ptr<type_die>
find_type_in_cu(shared_ptr<compile_unit_die> p_cu, const string& name)
{
	/* For the most part, we just do named_child.
	 * BUT, for base types, we widen the search, using our equivalence classes. */
	for (const char ***p_equiv = &cxx_compiler::base_typename_equivs[0]; *p_equiv != NULL; ++p_equiv)
	{
		for (const char **p_el = p_equiv[0]; *p_el != NULL; ++p_el)
		{
			if (name == string(*p_el))
			{
				/* We try every element in the class */
				for (const char **i_attempt = p_equiv[0]; *i_attempt != NULL; ++i_attempt)
				{
					auto found = p_cu->named_child(string(*i_attempt));
					auto found_type = dynamic_pointer_cast<type_die>(found);
					if (found_type) return found_type;
				}
			}
		}
	}

	// if we got here, just try named_child
	return dynamic_pointer_cast<type_die>(p_cu->named_child(name)); //shared_ptr<type_die>();
}

uniqued_name recursively_add_type(shared_ptr<spec::type_die> t, master_relation_t& r)
{
	if (!t) return make_pair("", "");
	t = t->get_concrete_type();
	
	/* If it's a base type, we might not have a decl_file, */
	if (!t->get_decl_file() || *t->get_decl_file() == 0)
	{
		if (t->get_tag() != DW_TAG_base_type
		 && t->get_tag() != DW_TAG_pointer_type
		 && t->get_tag() != DW_TAG_array_type)
		{
			cerr << "Warning: skipping non-base non-pointer non-array type described by " << *t //
			//if (t->get_name()) cerr << t->get_name();
			//else cerr << "(unknown, offset: " << std::hex << t->get_offset() << std::dec << ")";
			/*cerr */ << " because no file is recorded for its definition." << endl;
			return make_pair("", "");
		}
		// else it's a base type, so we go with the blank type
		// FIXME: should canonicalise base types here
		// (to the same as the ikind/fkinds come out from Cil.Pretty)
	}
	uniqued_name n = key_from_type(t);
	
	smatch m;
	//uniqued_name n = key_from_type(t);
	//if (r.find(n) != r.end())
	//cerr << "adding type " << n.second << " defined (or declared? FIXME) in file " << n.first << endl;
	if (r.find(n) != r.end()
		&& t->get_tag() != DW_TAG_base_type
		&& !regex_match(n.second, m, regex(".*__PTR_.*")))
	{
		//cerr << "warning: non-base non-pointer type named " << n.second << " already exists!" << endl;
	}
	r[n] = t;
	
	/* Now recurse on members */
	auto has_data_members = dynamic_pointer_cast<with_data_members_die>(t);
	if (!has_data_members) return n;
	for (auto i_child = has_data_members->member_children_begin();
		i_child != has_data_members->member_children_end(); ++i_child)
	{
		recursively_add_type((*i_child)->get_type(), r);
	}
	
	return n;
}

static string fq_pathname(const string& dir, const string& path)
{
	if (path.length() > 0 && path.at(0) == '/') return path;
	else return dir + "/" + path;
}

int main(int argc, char **argv)
{
	/* We read from stdin lines such as those output by dumpallocs,
	 * prefixed by their filename. Actually they will have been 
	 * stored in .allocsites files. */ 
	
	map<string, shared_ptr<ifstream> > ifstreams;
	map<string, shared_ptr<lib::file> > files;
	map<string, shared_ptr<lib::dieset> > diesets;
	map<string, core::root_die * > root_dies;
	
	std::shared_ptr<ifstream> p_in;
	if (argc > 1) 
	{
		p_in = std::make_shared<ifstream>(argv[1]);
		if (!*p_in) 
		{
			cerr << "Could not open file " << argv[1] << endl;
			return 1;
		}
	}
	std::istream& in = p_in ? *p_in : cin;
	
	master_relation_t master_relation;
	allocsites_relation_t allocsites_relation;
	subprograms_list_t subprograms_list;
	
	char buf[4096];
	string objname;
	string symname;
	unsigned file_addr;
	string sourcefile; 
	unsigned line;
	unsigned end_line;
	string alloc_typename;
	struct allocsite_to_add
	{
		string clean_typename;
		string sourcefile;
		string objname;
		unsigned file_addr;
	};
	
	vector<allocsite_to_add> allocsites_to_add;
	
	while (in.getline(buf, sizeof buf - 1)
		&& 0 == read_allocs_line(string(buf), objname, symname, file_addr, sourcefile, line, end_line, alloc_typename))
	{
		/* Open the dieset */
		if (ifstreams.find(objname) == ifstreams.end())
		{
			ifstreams.insert(make_pair(objname, make_shared<ifstream>(objname)));
			if (!*ifstreams[objname]) return 1;
			try
			{
				files.insert(make_pair(objname, make_shared<lib::file>(fileno(*ifstreams[objname]))));
				assert(files[objname]);
				diesets.insert(make_pair(objname, make_shared<lib::dieset>(*files[objname])));
				assert(diesets[objname]);
				root_dies.insert(make_pair(objname, 
					&dynamic_pointer_cast<lib::file_toplevel_die>(diesets[objname]->toplevel())
						->get_root()));
				assert(root_dies[objname]);
			} 
			catch (dwarf::lib::Error e)
			{
				// libdwarf(pp)? problem
				cerr << "libdwarf(pp)? error: " << dwarf::lib::dwarf_errmsg(e.e) << endl;
				return 1;
			}
		}
		// now assert we have what we need
		assert(ifstreams.find(objname) != ifstreams.end());
		assert(files.find(objname) != files.end());
		assert(diesets.find(objname) != diesets.end());		
		
		/* alloc_typename is in C declarator form.
		   What to do about this?
		   HACK: for now, support only a limited set of cases:
		   IDENT
		   IDENT '*'+
		   
		   AND delete the tokens "const", "volatile", "struct" and "union" first!
		   HACK: we are not respecting the C struct/union namespacing here. OH well.
		 */
		
		string nonconst_typename = alloc_typename;
		const char *to_delete[] = { "const", "volatile", "struct", "union" };
		for (int i = 0; i < srk31::array_len(to_delete); ++i)
		{
			size_t pos = 0;
			size_t foundpos;
			while ((foundpos = nonconst_typename.find(to_delete[i], pos)) != string::npos) 
			{
				/* Is this a well-bounded match, i.e. not part of a token? 
				 * - start must be beginning-of-string or following a non-a-zA-Z0-9_ char 
				 * - end must be end-of-string or followed by a non-a-zA-Z0-9_ char */
				size_t endpos = foundpos + string(to_delete[i]).length();
				if (
					(foundpos == 0 || (!isalnum(nonconst_typename[foundpos - 1]) 
					               &&  '_' != nonconst_typename[foundpos - 1] ))
				  && 
					(endpos == nonconst_typename.length()
					|| (!isalnum(nonconst_typename[endpos] || '_' != nonconst_typename[endpos])))
					)
				{
					/* it's a proper match -- delete that string and then start in the same place */
					nonconst_typename.replace(foundpos, endpos - foundpos, "");
					pos = foundpos;
				}
				else
				{
					/* It's not a proper match -- advance past this match. */
					pos = foundpos + 1;
				}
			}
		}
		//cerr << "After nonconsting, typename " << alloc_typename << " is " << nonconst_typename << endl;
		string clean_typename;
		
		smatch match;
		// HACK: we allow embedded spaces to allow "unsigned int" et al
		const regex ident("[[:blank:]]*([a-zA-Z_][a-zA-Z0-9_ ]*)[[:blank:]]*", egrep /*std::regex::awk*/);
		//const regex ident(" *([a-zA-Z0-9_]*) *", egrep);
		//const boost::regex ident_ptr("[[:blank:]]*([a-zA-Z_][a-zA-Z0-9]*)(([[:blank:]]*\\*)*)[[:blank:]]*");
		if (regex_match(nonconst_typename, match, ident))
		{
			clean_typename = match[0];
		}
		//else if (boost::regex_match(nonconst_typename, match, ident_ptr))
		else if (regex_match(nonconst_typename, match, regex("^(\\^+)(.*)", egrep)))
		{
			// this is a pointer. we need to fix on a single typename for these guys,
			// then (below) look in the dieset for an instance,
			// and assuming it's found (FIXME: it might not be present, theoretically)
			// generate it a unique name
			
			// with the new caret-based name, it's already clean! 
			clean_typename = nonconst_typename;
			
// 			clean_typename = match[0];
// 			unsigned stars_count = 0; 
// 			size_t pos = 0; 
// 			size_t foundpos;
// 			string matched_string = match[1];
// 			while ((foundpos = matched_string.find_first_of("*", pos)) != string::npos)
// 			{
// 				++stars_count;
// 				++foundpos;
// 			}
// 			for (int i = 0; i < stars_count; ++i) clean_typename += '*';
		}
		else if (regex_match(nonconst_typename, match, regex("\\$FAILED\\$", egrep)))
		{
			cerr << "skipping unidentified type at allocsite " 
			     << objname << "<" << symname << ">" 
				 << "@ 0x" << std::hex << file_addr << std::dec << endl;
			continue;
		}
		else
		{
			cerr << "warning: bad typename " << nonconst_typename 
				<< " from " << sourcefile << ":" << line << "-" << end_line << endl;
			continue;
		}
		boost::trim(clean_typename);
		
		allocsites_to_add.push_back((allocsite_to_add){ clean_typename, sourcefile, objname, file_addr });
	} // end while read line
	cerr << "Found " << allocsites_to_add.size() << " allocation sites across " << diesets.size()
		<< " binaries." << endl;
	
	/* At this point, we have processed all the allocation sites that we know about. 
	 * BUT we haven't processed all the data types that might be *tested* (e.g. for 
	 * tests that are going to fail, either because the are false or because we lack
	 * allocation info, or because stack and static are not implemented yet). So we 
	 * need to run through the entire DIEset looking for data types. With core::, this
	 * shouldn't take long. */
	using core::iterator_base;
	if (objname != "" && root_dies[objname])
	{
		for (auto i_d = root_dies[objname]->begin(); i_d != iterator_base::END; ++i_d)
		{
			if (i_d.spec_here().tag_is_type(i_d.tag_here()))
			{
				/* We've found a data type. */
			}
		}
	}
	
	// now we have all the diesets and CUs, build the subprograms list
	//for (auto i_cu = diesets[objname]->toplevel()->compile_unit_children_begin();
	//	 i_cu != diesets[objname]->toplevel()->compile_unit_children_end();
	//	 ++i_cu)
	if (objname != "" && root_dies[objname])
	{
		auto cus = root_dies[objname]->begin().children().subseq_of<core::compile_unit_die>();
		for (auto i_cu = std::move(cus.first); 
			 i_cu != cus.second;
			 ++i_cu)
		{
			/* First base is the non-downcasting iterator. Second is the non-filtering 
			 * iterator, i.e. the plain iterator_sibs. */
			auto& ii_cu = i_cu.base().base();
			cerr << "Found a CU at " << std::hex << ii_cu.offset_here() << std::dec << endl;
			/* Add this CU's subprograms to the subprograms list */
			/* FIXME: fix the memory leak!
			 * enabling/disabling the get_dynamic_location() line (way) below still has a huge
			 * impact on the memory consumption of the program. */

			/* This is no good because it doesn't construct a siblings_iterator. 
			 * We want to take the iterator returned by children_here, and 
			 * is_subprogram'ify it. */
			//pair<iterator_base::is_subprogram> subps = i_cu.children_here();

			//iterator_base::only_tag_seq<DW_TAG_subprogram> 

			// function template seems like the best value
			//auto subps = iterator_base::subseq< with_tag<DW_TAG_subprogram> >(i_cu.children_here())
			// how does this do the downcast?

			//auto subps
			// = iterator_base::subseq< iterator_base::is_a<core::subprogram_die> >(i_cu.children_here());

			auto children = ii_cu.children_here();
			//cerr << "First child is at 0x" << std::hex << children.first.offset_here() << std::dec << endl;
			auto subps = children.subseq_of<core::subprogram_die>();
			for (auto i_subp = std::move(subps.first); i_subp != subps.second; ++i_subp)
			{
				auto ii_subp = i_subp.base().base();

	// 			cerr << "Found a subprogram at 0x" << std::hex 
	// 				<< i_subp.base().base().base().offset_here() << std::dec
	// 				<< endl;
				// FIXME: fix base.base.base problem

				// FIXME: what if subprograms are not immediate children of their CU?
				// Want libdwarf to define a may_immediately_contain
				//                     and   may_recursively_contain (transitive closure)
				// lookup, then generalise increment_skipping_subtree
				// to a search specifying a tag, which can skip subtrees (whether doing dfs or bfs)
				// if the DIEs we're looking for cannot possibly be underneath.

				// problem dereferencing transform_iterators: 
				// seems to be something to do with shared_ptr versus intrusive_ptr.
				// What it's doing:
				// dereference the base()
				// apply the functor to the result
				// return a *reference* implicitly constructed from the functor's output
				// 
				// Here the base() is our selective_iterator
				// dereferencing it yields what? should be a basic_die&
				// SOMEHOW it is getting called with an iterator_facade. 
				// THAT does not make sense -- we apply the functor to the dereferenced base
				// WHAT do we get when we dereference our filter_iterator?
				// It's a srk31::selective_iterator<Iter>
				// We get Iter::value_type.
				// What's Iter? It's our subseq_t's Iter. What's that? It's iterator_sibs<>.
				// So what's iterator_sibs<>'s value_type? It's basic_die.

				// NOT an intrusive_ptr to which we want to return a reference
				// (which would be BAD! we'd need 
				// to make reference_type on the selective_iterator just the intrusive_ptr

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
					if (i_subp->get_name()) subp_name = *i_subp->get_name();
					else 
					{
						std::ostringstream s;
						s << "0x" << std::hex << ii_subp.offset_here();
						subp_name = s.str();
					}

					auto ret = subprograms_list.insert(
						make_pair(
							make_pair(
								fq_pathname(comp_dir, sourcefile_name),
								subp_name
							), 
							// now we want an iterator_sibs<subprogram_die> 
							i_subp.base().base()
						)
					);
					if (!ret.second)
					{
						/* This means that "the same value already existed". */
						//cerr << "Warning: subprogram " << **i_subp
						//	<< " already in subprograms_list as " 
						//	<< ret.first->first.second << " in " << ret.first->first.first << ": "
						//	<< **ret.first->second
						//	<< endl;
					}
				}
			}
		} // end for cu
	}
	else
	{
		if (objname != "") cerr << "Warning: no DIEs for " << objname << endl;
	}
	cerr << "Found " << subprograms_list.size() << " subprograms." << endl;
	
	for (auto i_alloc = allocsites_to_add.begin(); i_alloc != allocsites_to_add.end(); ++i_alloc)
	{
		/* Build the containment structure and topsort it. 
		 * It only needs to reflect the allocated types. So,
		 * traverse the type depthfirst. */
		
		string clean_typename = i_alloc->clean_typename;
		string sourcefile = i_alloc->sourcefile;
		string objname = i_alloc->objname;
		unsigned file_addr = i_alloc->file_addr;
		
		
		shared_ptr<compile_unit_die> found_cu;
		optional<string> found_sourcefile_path;
		shared_ptr<type_die> found_type;
		/* Find a CU such that 
		 - one of its source files is named sourcefile, taken relative to comp_dir if necessary;
		 - that file defines a type of the name we want
		 */ 
		
		std::vector<shared_ptr<compile_unit_die> > embodying_cus;
		
		for (auto i_cu = diesets[objname]->toplevel()->compile_unit_children_begin();
			 i_cu != diesets[objname]->toplevel()->compile_unit_children_end();
			 ++i_cu)
		{
			if ((*i_cu)->get_name() && (*i_cu)->get_comp_dir())
			{
				auto cu_die_name = *(*i_cu)->get_name();
				auto cu_comp_dir = *(*i_cu)->get_comp_dir();
				
				for (unsigned i_srcfile = 1; i_srcfile <= (*i_cu)->source_file_count(); i_srcfile++)
				{
					/* Does this source file have a matching name? */
					string current_sourcepath;
					string cu_srcfile_mayberelative = (*i_cu)->source_file_name(i_srcfile);
					//cerr << "CU " << *(*i_cu)->get_name() << " sourcefile " << i_srcfile << " is " <<
					//	cu_srcfile_mayberelative << endl;
					//if (!path(cu_srcfile_mayberelative).has_root_directory())
					if (cu_srcfile_mayberelative.length() > 0 && cu_srcfile_mayberelative.at(0) != '/')
					{ 
						current_sourcepath = cu_comp_dir + '/' + cu_srcfile_mayberelative;
					}
					else current_sourcepath = /*path(*/cu_srcfile_mayberelative/*)*/;
					
					// FIXME: smarter search
					// FIXME: look around a bit, since sizeof isn't enough to keep DIE in the object file
					if (current_sourcepath == /*path(*/sourcefile/*)*/)
					{ 
						// YES this CU embodies the source file, so we can search for the type
						embodying_cus.push_back(*i_cu);
						
						// handle pointers here
						// HACK: find *any* pointer type,
						// and use that, with empty sourcefile.
						if (clean_typename.size() > 0 && *clean_typename.begin() == '^')
						{
							if ((*i_cu)->pointer_type_children_begin()
								== (*i_cu)->pointer_type_children_end())
							{
								cerr << "Warning: no pointer type children in CU! Trying the next one." << endl;
								continue;
							}
							else
							{
								found_cu = *i_cu;
								found_type = *(*i_cu)->pointer_type_children_begin();
								found_sourcefile_path = current_sourcepath;
								goto cu_loop_exit;
							}
						}
						else
						{
							found_type = find_type_in_cu(*i_cu, clean_typename);
							if (found_type/* && (
										found_type->get_tag() == DW_TAG_base_type ||
										(found_type->get_decl_file()
											&& *found_type->get_decl_file() == i_srcfile))*/)
							{
								found_cu = *i_cu;
								found_sourcefile_path = current_sourcepath;
								goto cu_loop_exit;
							}
							else found_type = shared_ptr<type_die>();
						}
					}
				}
			}
		} // end for each CU
	cu_loop_exit:
		if (!found_type)
		{
			cerr << "Warning: no type named " << clean_typename 
				<< " in CUs (found " << embodying_cus.size() << ":";
				for (auto i_cu = embodying_cus.begin(); i_cu != embodying_cus.end(); ++i_cu)
				{
					if (i_cu != embodying_cus.begin()) cerr << ", ";
					cerr << *(*i_cu)->get_name();
				}
				cerr << ") embodying " 
				<< sourcefile << ":" << line << "-" << end_line
				<< " (allocsite: " << objname 
				<< "<" << symname << "> @" << std::hex << file_addr << std::dec << ">)" << endl;
			continue; // next allocsite
		}
		// now we found the type
		//cerr << "SUCCESS: found type: " << *found_type << endl;

		uniqued_name name_used = recursively_add_type(found_type, master_relation);

		// add to the allocsites table too
		// recall: this is the mapping from allocsites to uniqtype addrs
		// the uniqtype addrs are given as idents, so we just have to use the same name
		allocsites_relation.insert(
			make_pair(
				make_pair(objname, file_addr),
				name_used
			)
		);
	} // end for allocsite

	cerr << "Master relation contains " << master_relation.size() << " data types." << endl;
	
	// concept checks for graph
	boost::function_requires< 
		boost::InputIterator<
			boost::graph_traits<master_relation_t>::out_edge_iterator
		>
	> ();
	boost::function_requires< boost::IncidenceGraphConcept<master_relation_t> >();
	
	// now topsort
	std::map<
		boost::graph_traits<master_relation_t>::nonconst_vertex_descriptor, 
		boost::default_color_type
	> underlying_topsort_node_color_map;
	auto topsort_color_map = boost::make_assoc_property_map( // ColorMap provides a mutable "Color" property per node
		underlying_topsort_node_color_map
	);
	auto named_params = boost::color_map(topsort_color_map);

	container topsorted_container;
	boost::topological_sort(
		master_relation, 
		std::back_inserter(topsorted_container), 
		named_params
	);
	
	// now print .c file in topsorted order
	print_uniqtypes_output(master_relation, topsorted_container);
	print_stacktypes_output(subprograms_list);
	print_allocsites_output(allocsites_relation);
	
	// success! 
	return 0;
}

void print_uniqtypes_output(const master_relation_t& g, const container& c)
{
	/* For each type we output a record:
	 * - a pointer to its name;
	 * - a length prefix;
	 * - a list of <offset, included-type-record ptr> pairs.
	 */

	cout << "struct rec \n\
{ \n\
	const char *name; \n\
	unsigned sz; \n\
	unsigned len; \n\
	struct { \n\
		signed offset; \n\
		struct rec *ptr; \n\
	} contained[]; \n\
};\n";
	/* DWARF doesn't reify void, but we do. So output a rec for void first of all. */
	cout << "\n/* uniqtype for void */\n";
	cout << "struct rec " << mangle_typename(make_pair(string(""), string("void")))
		<< " = {\n\t\"" << "void" << "\",\n\t"
		<< "0" << " /* sz " << "(void) */,\n\t"
		<< "0" << " /* len */,\n\t"
		<< "/* contained */ { }\n};";

	for (auto i_vert = c.begin(); i_vert != c.end(); ++i_vert)
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
				<< *i_vert->second->enclosing_compile_unit()->get_name()
				<< endl;
			continue;
		}
		
		cout << "\n/* uniqtype for " << i_vert->first.second 
			<< " defined in " << i_vert->first.first << " */\n";
		cout << "struct rec " << mangle_typename(i_vert->first)
			<< " = {\n\t\"" << i_vert->first.second << "\",\n\t"
			<< (opt_sz ? *opt_sz : 0) << " /* sz " << (opt_sz ? "" : "(incomplete) ") << "*/,\n\t"
			<< boost::out_degree(*i_vert, g) << " /* len */,\n\t"
			<< /* contained[0] */ "/* contained */ {\n\t\t";
		auto out_edges = boost::out_edges(*i_vert, g);
		unsigned i_member = 0;
		std::set<lib::Dwarf_Unsigned> used_offsets;
		for (auto i_edge = out_edges.first; i_edge != out_edges.second; ++i_edge)
		{
			++i_member;
		
			/* if we're not the first, write a comma */
			if (i_edge != out_edges.first) cout << ",\n\t\t";
			
			/* begin the struct */
			cout << "{ ";
			
			// compute offset
			lib::Dwarf_Unsigned offset;
			if ((*i_edge)->get_data_member_location() 
				&& (*i_edge)->get_data_member_location()->size() > 0)
			{
				
				if ((*i_edge)->get_data_member_location()->size() > 1)
				{
					cerr << "Warning: ignoring all but first location expression for "
						<< i_member << srk31::ordinal_suffix(i_member) << " data member of " 
						<< i_vert->first.second << endl;
				}
				offset = lib::evaluator(
					(*i_edge)->get_data_member_location()->at(0), (*i_edge)->get_ds().get_spec(),
					// push zero as the initial stack value
					std::stack<lib::Dwarf_Unsigned>(std::deque<lib::Dwarf_Unsigned>(1, 0UL))).tos();
			}
			else 
			{
				cerr << "Warning: "
					<< i_member << srk31::ordinal_suffix(i_member) << " data member of " 
					<< i_vert->first.second 
					<< " has no location description; assuming zero-offset." 
					<< endl;
				offset = 0UL;
			}
			// check whether this subobject overlaps another
			if (used_offsets.find(offset) != used_offsets.end())
			{
				// FIXME: do overlapment check
				cerr << "Warning: "
					<< i_member << srk31::ordinal_suffix(i_member) << " data member of " 
					<< i_vert->first.second 
					<< " shares offset with a previous member." 
					<< endl;
			}
			
			cout << offset << ", ";
			
			// compute and print destination name
			cout << "&" << mangle_typename(boost::target(*i_edge, g).first);
			
			// end the struct
			cout << " }";
		}
		cout << "\n\t}"; /* end contained */
		cout << "\n};\n"; /* end struct rec */
	}
}

void print_stacktypes_output(const subprograms_list_t& l)
{
	/* For each subprogram, for each vaddr range for which its
	 * stack frame is laid out differently, output a uniqtype record.
	 * We do this by
	 * - collecting all local variables and formal parameters on a depthfirst walk;
	 * - collecting their vaddr ranges into a partition, splitting any overlapping ranges
	     and building a mapping from each range to the variables/parameters valid in it;
	 * - when we're finished, outputting a distinct uniqtype for each range;
	 * - also, output a table of IPs-to-uniqtypes.  */
	using dwarf::lib::Dwarf_Off;
	using dwarf::lib::Dwarf_Addr;
	using dwarf::lib::Dwarf_Signed;
	using dwarf::lib::Dwarf_Unsigned;
	using dwarf::spec::with_dynamic_location_die;
	
	for (auto i_i_subp = l.begin(); i_i_subp != l.end(); ++i_i_subp)
	{
		auto i_subp = i_i_subp->second;
		
		boost::icl::interval_map< Dwarf_Off, std::set< shared_ptr<with_dynamic_location_die> > >
		subp_vaddr_intervals; // CU- or file-relative?

		/* Put this subp's vaddr ranges into the map */
		//auto subp_intervals = (*i_subp)->file_relative_intervals(
		//	0 /* FIXME: write a symbol resolver -- do we need this? can just pass 0? */
		//);
		
// HACK while our iterator interfaces don't directly provide a depth method
#define GET_DEPTH(i)  ((i).base().path_from_root.size()) 
		
		/* Earlier, we stored core:: iterators in the subprograms_map. 
		 * Now, we need spec:: ADT methods which I haven't yet ported
		 * to core::. So, we need to construct an ADT iterator.
		 * OR port to the new API. */
		core::iterator_df<> start_df(i_subp);
		
// 		dwarf::spec::abstract_dieset::iterator start_dfs(
// 			*i_subp.base().p_ds, i_subp.base().off, i_subp.base().path_from_root
// 		);
		
//		unsigned subp_depth = GET_DEPTH(start_dfs);
		unsigned initial_depth = start_df.depth();
//		++start_dfs; // now we point to the first child, or somewhere else if no children
		++start_df;
		
// 		using dwarf::spec::abstract_dieset;
// 		// don't go DFS; go BFS
// 		// so that we can skip nested types (which may contain methods,
// 		// which may contain formal_parameters, which are *not* fps of
// 		// the frame we're considering). 
// 		// Note that BFS will explore siblings first, so we need to make sure
// 		// we're *under* the subprogram -- use DFS for this.
// 		struct skip_types_policy : public abstract_dieset::bfs_policy
// 		{
// 			int increment(dwarf::spec::abstract_dieset::iterator_base& base)
// 			{
// 				if (dynamic_pointer_cast<spec::type_die>(base.p_d))
// 				{
// 					return increment_skipping_subtree(base);
// 				} else return this->bfs_policy::increment(base);
// 			}
// 		} policy;
		
		struct iterator_bf_skipping_types : public core::iterator_bf<>
		{
			void increment()
			{
				if (spec_here().tag_is_type(tag_here()))
				{
					increment_skipping_subtree();
				} else increment();
			}			
			// constructors: forward from 
			//using core::iterator:bf::iterator:bf;
			//template<typename... Args>
			// Can't have member template in local class
			//iterator_bf_skipping_types(Args&&... args)
			//: core::iterator_bf(std::forward<Args>(args)...) {}
			
			// for now, just declare the one we need!
			typedef core::iterator_bf<> base;
			iterator_bf_skipping_types(iterator_base& i) : base(i) {}
		} start_bf(start_df);
		
// 		// get a *dfs* iterator -- HACK
// 		abstract_dieset::iterator start_bfs(
// 			abstract_dieset::position_and_path(
// 				(abstract_dieset::position) {
// 					start_dfs.base().p_ds, 
// 					start_dfs.base().off
// 				},
// 				start_dfs.base().path_from_root),
// 			/* p_d */ shared_ptr<dwarf::spec::basic_die>(),
// 			policy
// 		);

// 		for (auto i_bfs = start_bfs; 
// 			i_bfs != start_dfs.base().p_ds->end()
// 			  && (i_bfs == start_bfs || GET_DEPTH(i_bfs) > subp_depth); 
// 			++i_bfs)
		for (auto i_bf = start_bf;
			i_bf != core::iterator_base::END
			&& (i_bf == start_bf || i_bf.depth() > initial_depth); 
			++i_bf)
		{
		
// 			// skip if not a with_dynamic_location_die
// 			shared_ptr<with_dynamic_location_die> p_dyn
// 			 = dynamic_pointer_cast<with_dynamic_location_die>(*i_bfs);
// 			if (!p_dyn) continue;
// 		
// 			/* Exploit "clever" (hopefully) aggregation semantics of 
// 			 * interval maps.
// 			 * http://www.boost.org/doc/libs/1_51_0/libs/icl/doc/html/index.html
// 			 */
// 			
// 			// enumerate the vaddr ranges of this DIE
// 			// -- note that some DIEs will be "for all vaddrs"
// 			// -- noting also that static variables need handling!
// 			//    ... i.e. they need to be handled in the *static* handler!
// 			auto p_as_var = dynamic_pointer_cast<spec::variable_die>(p_dyn);
// 			if (p_as_var && p_as_var->has_static_storage()) continue;
// 			
// 			auto var_vaddr_intervals = p_dyn->get_dynamic_location();
// 			
// 			// for each, add it to the map
// 			for (auto i_int = var_vaddr_intervals.begin(); 
// 				i_int != var_vaddr_intervals.end(); ++i_int)
// 			{
// 				std::set<shared_ptr<with_dynamic_location_die> > singleton_set;
// 				singleton_set.insert(p_dyn);
// 				
// 				if (i_int->lopc == 0xffffffffffffffffULL
// 				|| i_int->lopc == 0xffffffffUL)
// 				{
// 					// we got a base address selection entry
// 					assert(false);
// 				}
// 				
// 				if (i_int->lopc == i_int->hipc && i_int->hipc != 0) continue; // skip empties
// 				if (i_int->hipc <  i_int->lopc)
// 				{
// 					cerr << "Warning: lopc (0x" << std::hex << i_int->lopc << std::dec
// 						<< ") > hipc (0x" << std::hex << i_int->hipc << std::dec << ")"
// 						<< " in " << *p_dyn << endl;
// 					continue;
// 				}
// 				
// 				auto opt_cu_base = (*i_subp)->enclosing_compile_unit()->get_low_pc();
// 				Dwarf_Unsigned cu_base = opt_cu_base->addr;
// 				
// 				// handle "for all vaddrs" entries
// 				boost::icl::discrete_interval<Dwarf_Off> our_interval;
// 				if (i_int->lopc == 0 && 0 == i_int->hipc
// 					|| i_int->lopc == 0 && i_int->hipc == std::numeric_limits<Dwarf_Off>::max())
// 				{
// 					/* we will just add the intervals of the containing subprogram */
// 					auto subp_intervals = (*i_subp)->file_relative_intervals(0, 0);
// 					for (auto i_subp_int = subp_intervals.begin();
// 						i_subp_int != subp_intervals.end(); 
// 						++i_subp_int)
// 					{
// 						our_interval = boost::icl::interval<Dwarf_Off>::right_open(
// 							i_subp_int->first.lower() + cu_base,
// 							i_subp_int->first.upper() + cu_base
// 						);
// 						
// 						cerr << "Borrowing vaddr ranges of " << **i_subp
// 							<< " for dynamic-location " << *p_dyn;
// 						
// 						/* assert sane interval */
// 						assert(our_interval.lower() < our_interval.upper());
// 						/* assert sane size -- no bigger than biggest sane function */
// 						assert(our_interval.upper() - our_interval.lower() < 1024*1024);
// 						subp_vaddr_intervals += make_pair(
// 							our_interval,
// 							singleton_set
// 						); 
// 					}
// 					/* There should be only one entry in the location list if so. */
// 					assert(i_int == var_vaddr_intervals.begin());
// 					assert(i_int + 1 == var_vaddr_intervals.end());
// 				}
// 				else /* we have nonzero lopc and/or hipc */
// 				{
// 					our_interval = boost::icl::interval<Dwarf_Off>::right_open(
// 						i_int->lopc + cu_base, i_int->hipc + cu_base
// 					); 
// 					
// 					cerr << "Considering location of " << *p_dyn << endl;
// 					
// 					/* assert sane interval */
// 					assert(our_interval.lower() < our_interval.upper());
// 					/* assert sane size -- no bigger than biggest sane function */
// 					assert(our_interval.upper() - our_interval.lower() < 1024*1024);
// 					subp_vaddr_intervals += make_pair(
// 						our_interval,
// 						singleton_set
// 					); 
// 				}
// 				
// 			}
// 			
// 			/* We note that the map is supposed to map file-relative addrs
// 			 * (FIXME: vaddr is CU- or file-relative? or "applicable base address" blah?) 
// 			 * to the set of variable/fp DIEs that are 
// 			 * in the current (top) stack frame when the program counter is at that vaddr. */
		} /* end bfs */
// #undef GET_DEPTH
// 
// 		/* Now we write a *series* of object layouts for this subprogram, 
// 		 * discriminated by a set of (disjoint) vaddr ranges. */
// 		
// 		/* Our naive earlier algorithm had the problem that, once register-based 
// 		 * locals are discarded, the frame layout is often unchanged from one vaddr range
// 		 * to the next. But we were outputting a new uniqtype anyway, creating 
// 		 * huge unnecessary bloat. So instead, we do a pre-pass where we remember
// 		 * only the stack-located elements, and store them in a new interval map, 
// 		 * by offset from frame base. 
// 		 *
// 		 * Also, we want to report discarded fps/locals once per subprogram, as 
// 		 * completely discarded or partially discarded. How to do this? 
// 		 * Keep an interval map of discarded items.
// 		 * When finished, walk it and build another map keyed by 
// 		  */
// 		boost::icl::interval_map< 
// 			Dwarf_Off, 
// 			std::set< 
// 				pair<
// 					Dwarf_Signed, 
// 					shared_ptr<with_dynamic_location_die> 
// 				> 
// 			>
// 		> frame_intervals;
// 		boost::icl::interval_map< 
// 			Dwarf_Off, 
// 			std::set< 
// 				pair<
// 					shared_ptr<with_dynamic_location_die>,
// 					string
// 				>
// 			>
// 		> discarded_intervals;
// 		 
// 		for (auto i_int = subp_vaddr_intervals.begin(); 
// 			i_int != subp_vaddr_intervals.end(); ++i_int)
// 		{
// 			/* Get the set of p_dyns for this vaddr range. */
// 			auto& frame_elements = i_int->second;
// 			
// 			/* Calculate their offset from the frame base, and sort. */
// 			//std::map<Dwarf_Signed, shared_ptr<with_dynamic_location_die > > by_frame_off;
// 			//std::vector<pair<shared_ptr<with_dynamic_location_die >, string> > discarded;
// 			for (auto i_el = frame_elements.begin(); i_el != frame_elements.end(); ++i_el)
// 			{
// 				/* NOTE: our offset can easily be negative! For parameters, it 
// 				 * usually is. So we calculate the offset from the middle of the 
// 				 * (imaginary) address space, a.k.a. 1U<<((sizeof(Dwarf_Addr)*8)-1). 
// 				 * In a signed two's complement representation, 
// 				 * this number is -MAX. 
// 				 * NO -- just reinterpret_cast to a signed? */ 
// 				Dwarf_Addr addr_from_zero;
// 				try
// 				{
// 					addr_from_zero = (*i_el)->calculate_addr(
// 						/* fb */ 0, //1U<<((sizeof(Dwarf_Addr)*8)-1), 
// 						/* dr_ip */ i_int->first.lower(), 
// 						/* dwarf::lib::regs *p_regs = */ 0);
// 				} catch (dwarf::lib::No_entry)
// 				{
// 					/* This probably means our variable/fp is in a register and not 
// 					 * in a stack location. That's fine. Warn and continue. */
// 					cerr << "Warning: we think this is a register-located local/fp or pass-by-reference fp: " 
// 						<< **i_el;
// 					//discarded.push_back(make_pair(*i_el, "register-located"));
// 					set< pair< shared_ptr< with_dynamic_location_die >, string> > singleton_set;
// 					singleton_set.insert(make_pair(*i_el, string("register-located")));
// 					discarded_intervals += make_pair(i_int->first, singleton_set);
// 					continue;
// 				}
// 				
// 				Dwarf_Signed frame_offset = static_cast<Dwarf_Signed>(addr_from_zero);
// 					
// 				/* Redundant calculation to guard against arithmetic errors 
// 				 * TODO: remove this once we have confidence. */
// 				Dwarf_Addr addr_from_beef = (*i_el)->calculate_addr(
// 					/* fb */ 0xbeef,
// 					/* dr_ip */ i_int->first.lower(), 
// 					/* dwarf::lib::regs *p_regs = */ 0);
// 				
// 				/* Some fb-independent addrs might have slipped though. */
// 				if (frame_offset == addr_from_beef)
// 				{
// 					cerr << "Warning: found fb-independent " << **i_el
// 						<< " which we thought had non-static storage." << endl;
// 					//discarded.push_back(make_pair(*i_el, "fb-independent storage location"));
// 					set< pair< shared_ptr< with_dynamic_location_die >, string> > singleton_set;
// 					singleton_set.insert(make_pair(*i_el, string("fb-independent storage location")));
// 					discarded_intervals += make_pair(i_int->first, singleton_set);
// 					continue;
// 				}
// 				assert(frame_offset + 0xbeef == addr_from_beef);
// 				
// 				/* We only add to by_frame_off if we have complete type => nonzero length. */
// 				if ((*i_el)->get_type() && (*i_el)->get_type()->get_concrete_type())
// 				{
// 					//by_frame_off[frame_offset] = *i_el;
// 					set< pair<Dwarf_Signed, shared_ptr<with_dynamic_location_die> > > singleton_set;
// 					singleton_set.insert(make_pair(frame_offset, *i_el));
// 					frame_intervals += make_pair(i_int->first, singleton_set);
// 				} 
// 				else
// 				{ 
// 					set< pair< shared_ptr< with_dynamic_location_die >, string> > singleton_set;
// 					singleton_set.insert(make_pair(*i_el, string("no_concrete_type")));
// 					discarded_intervals += make_pair(i_int->first, singleton_set);
// 					//discarded.push_back(make_pair(*i_el, "no concrete type"));
// 				}
// 			}
// 		} /* end for i_int */
// 		
// 		/* Now for each distinct interval in the frame_intervals map... */
// 		for (auto i_frame_int = frame_intervals.begin(); i_frame_int != frame_intervals.end();
// 			++i_frame_int)
// 		{
// 			unsigned frame_size;
// 			//if (by_frame_off.begin() == by_frame_off.end()) frame_size = 0;
// 			if (i_frame_int->second.size() == 0) frame_size = 0;
// 			else
// 			{
// 				// FIXME: this frame size is "wrong" because it doesn't account for 
// 				// the negative-offset portion of the frame. 
// 				//auto i_last_el = by_frame_off.end(); --i_last_el;
// 				
// 				auto i_last_el = i_frame_int->second.end(); --i_last_el;
// 				
// 				auto p_type = i_last_el->second->get_type();
// 				unsigned calculated_size;
// 				if (!p_type || !p_type->get_concrete_type() || !p_type->calculate_byte_size())
// 				{
// 					cerr << "Warning: found local/fp with no type or size (assuming zero length): " 
// 						<< *i_last_el->second;
// 					calculated_size = 0;
// 				}
// 				else calculated_size = *p_type->calculate_byte_size();
// 				signed frame_max_offset = i_last_el->first + calculated_size;
// 				frame_size = (frame_max_offset < 0) ? 0 : frame_max_offset;
// 			}
// 			
// 			/* Output in offset order, CHECKing that there is no overlap (sanity). */
// 			cout << "\n/* uniqtype for stack frame ";
// 			std::ostringstream s_typename;
// 			if ((*i_subp)->get_name()) s_typename << *(*i_subp)->get_name();
// 			else s_typename << "0x" << std::hex << (*i_subp)->get_offset() << std::dec;
// 			
// 			s_typename << "_vaddrs_0x" << std::hex << i_frame_int->first.lower() << "_0x" 
// 				<< i_frame_int->first.upper() << std::dec;
// 			
// 			string cu_name = *(*i_subp)->enclosing_compile_unit()->get_name();
// 			
// 			cout << s_typename.str() 
// 				 << " defined in " << cu_name << ", "
// 				 << "vaddr range " << i_frame_int->first << " */\n";
// 				 
// 			cout << "struct rec " << mangle_typename(make_pair(cu_name, s_typename.str()))
// 				<< " = {\n\t\"" << s_typename.str() << "\",\n\t"
// 				<< frame_size << " /* sz */,\n\t"
// 				<< i_frame_int->second.size() << " /* len */,\n\t"
// 				<< /* contained[0] */ "/* contained */ {\n\t\t";
// 			for (auto i_by_off = i_frame_int->second.begin(); i_by_off != i_frame_int->second.end(); ++i_by_off)
// 			{
// 				if (i_by_off != i_frame_int->second.begin()) cout << ",\n\t\t";
// 				/* begin the struct */
// 				cout << "{ ";
// 				cout << i_by_off->first << ", "
// 					<< "&" << mangle_typename(key_from_type(i_by_off->second->get_type()))
// 					<< "}";
// 				cout << " /* ";
// 				if (i_by_off->second->get_name())
// 				{
// 					cout << *i_by_off->second->get_name();
// 				}
// 				else cout << "(anonymous)"; 
// 				cout << " -- " << i_by_off->second->get_spec().tag_lookup(
// 						i_by_off->second->get_tag())
// 					<< " @" << std::hex << i_by_off->second->get_offset() << std::dec;
// 				cout << " */ ";
// 			}
// 			cout << "\n\t}";
// 			cout << "\n};\n";
// 		}
// 		/* Now print a summary of what was discarded. */
// // 		for (auto i_discarded = discarded.begin(); i_discarded != discarded.end(); 
// // 			++i_discarded)
// // 		{
// // 			cout << "\n\t/* discarded: ";
// // 			if (i_discarded->first->get_name())
// // 			{
// // 				cout << *i_discarded->first->get_name();
// // 			}
// // 			else cout << "(anonymous)"; 
// // 			cout << " -- " << i_discarded->first->get_spec().tag_lookup(
// // 					i_discarded->first->get_tag())
// // 				<< " @" << std::hex << i_discarded->first->get_offset() << std::dec;
// // 			cout << "; reason: " << i_discarded->second;
// // 			cout << " */ ";
// // 		}
	}
}

void print_allocsites_output(const allocsites_relation_t& r)
{
	cout << "struct allocsite_entry\n\
{ \n\
	void *next; \n\
	void *prev; \n\
	void *allocsite; \n\
	struct rec *uniqtype; \n\
};\n";	

	cout << "struct allocsite_entry allocsites[] = {" << endl;
	for (auto i_site = r.begin(); i_site != r.end(); ++i_site)
	{
		if (i_site != r.begin()) cout << ",";
		
		cout << "\n\t/* allocsite info for " << i_site->first.first << "+"
			<< std::hex << "0x" << i_site->first.second << std::dec << " */";
		cout << "\n\t{ (void*)0, (void*)0, "
			<< "(char*) " << "__LOAD_ADDR_" 
			<< boost::to_upper_copy(mangle_objname(i_site->first.first))
			<< " + " << i_site->first.second << "UL, " 
			<< "&" << mangle_typename(i_site->second)
			<< " }";
	}
	// output a null terminator entry
	if (r.size() > 0) cout << ",";
	cout << "\n\t{ (void*)0, (void*)0, (void*)0, (struct rec *)0 }";
	
	// close the list
	cout << "\n};\n";
}

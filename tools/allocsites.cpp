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
#include <boost/algorithm/string.hpp>
#include <boost/regex.hpp>
// #include <regex> // broken in GNU libstdc++!
//#include <boost/filesystem.hpp>
#include <srk31/algorithm.hpp>
#include <srk31/ordinal.hpp>
#include <fileno.hpp>

#include "helpers.hpp"

using std::cin;
using std::cout;
using std::cerr;
using std::map;
using std::ios;
using std::ifstream;
using boost::optional;
using std::ostringstream;
using namespace dwarf;
//using boost::filesystem::path;
using dwarf::core::root_die;
using dwarf::core::iterator_base;
using dwarf::core::iterator_df;
using dwarf::core::iterator_sibs;
using dwarf::core::type_die;
using dwarf::core::subprogram_die;
using dwarf::core::compile_unit_die;
using dwarf::core::pointer_type_die;

// regex usings
using boost::regex;
using boost::regex_match;
using boost::smatch;
using boost::regex_constants::egrep;
using boost::match_default;
using boost::format_all;

typedef std::map< pair< string, unsigned long >, uniqued_name > allocsites_relation_t;

int main(int argc, char **argv)
{
	/* We read from stdin lines such as those output by dumpallocs,
	 * prefixed by their filename. Actually they will have been 
	 * stored in .allocsites files. */ 
	
	using std::unique_ptr;
	unique_ptr<std::ifstream> p_objfile;
	unique_ptr<root_die> p_root;
	
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
	
	allocsites_relation_t allocsites_relation;
	
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
	
	optional<string> seen_objname;
	
	while (in.getline(buf, sizeof buf - 1)
		&& 0 == read_allocs_line(string(buf), objname, symname, file_addr, sourcefile, line, end_line, alloc_typename))
	{
		if (!seen_objname)
		{
			seen_objname = objname;
			p_objfile = unique_ptr<std::ifstream>(new std::ifstream(*seen_objname));
			if (!*p_objfile)
			{
				assert(false);
			}
			p_root = unique_ptr<root_die>(new root_die(fileno(*p_objfile)));
			assert(p_root);
		}
		else assert(*seen_objname == objname);

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
	cerr << "Found " << allocsites_to_add.size() << " allocation sites" << endl;
	
	for (auto i_alloc = allocsites_to_add.begin(); i_alloc != allocsites_to_add.end(); ++i_alloc)
	{
		string clean_typename = i_alloc->clean_typename;
		string sourcefile = i_alloc->sourcefile;
		string objname = i_alloc->objname;
		unsigned file_addr = i_alloc->file_addr;
		
		iterator_df<compile_unit_die> found_cu;
		optional<string> found_sourcefile_path;
		iterator_df<type_die> found_type;
		/* Find a CU such that 
		 - one of its source files is named sourcefile, taken relative to comp_dir if necessary;
		 - that file defines a type of the name we want
		 */ 
		
		std::vector<iterator_df<compile_unit_die> > embodying_cus;
		auto cus = p_root->begin().children();
		for (iterator_sibs<compile_unit_die> i_cu = cus.first;
			 i_cu != cus.second; ++i_cu)
		{
			if (i_cu->get_name() && i_cu->get_comp_dir())
			{
				auto cu_die_name = *i_cu->get_name();
				auto cu_comp_dir = *i_cu->get_comp_dir();
				
				for (unsigned i_srcfile = 1; i_srcfile <= i_cu->source_file_count(); i_srcfile++)
				{
					/* Does this source file have a matching name? */
					string current_sourcepath;
					string cu_srcfile_mayberelative = i_cu->source_file_name(i_srcfile);
					//cerr << "CU " << *i_cu->get_name() << " sourcefile " << i_srcfile << " is " <<
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
						embodying_cus.push_back(i_cu);
						
						// handle pointers here
						// HACK: find *any* pointer type,
						// and use that, with empty sourcefile.
						if (clean_typename.size() > 0 && *clean_typename.begin() == '^')
						{
							auto toplevel_pointers = i_cu.children().subseq_of<pointer_type_die>();
							if (toplevel_pointers.first == toplevel_pointers.second)
							{
								cerr << "Warning: no pointer type children in CU! Trying the next one." << endl;
								continue;
							}
							else
							{
								found_cu = i_cu;
								found_type = toplevel_pointers.first.base().base();
								found_sourcefile_path = current_sourcepath;
								goto cu_loop_exit;
							}
						}
						else
						{
							found_type = find_type_in_cu(i_cu, clean_typename);
							if (found_type/* && (
										found_type->get_tag() == DW_TAG_base_type ||
										(found_type->get_decl_file()
											&& *found_type->get_decl_file() == i_srcfile))*/)
							{
								found_cu = i_cu;
								found_sourcefile_path = current_sourcepath;
								goto cu_loop_exit;
							}
							else found_type = iterator_base::END;
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

		uniqued_name name_used = canonical_key_from_type(found_type);

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

	cout << "struct allocsite_entry\n\
{ \n\
	void *next; \n\
	void *prev; \n\
	void *allocsite; \n\
	struct rec *uniqtype; \n\
};\n";

	// extern-declare the uniqtypes
	for (auto i_site = allocsites_relation.begin(); i_site != allocsites_relation.end(); ++i_site)
	{
		cout << "extern struct rec " << mangle_typename(i_site->second) << ";" << endl;
	}

	cout << "struct allocsite_entry allocsites[] = {" << endl;
	for (auto i_site = allocsites_relation.begin(); i_site != allocsites_relation.end(); ++i_site)
	{
		if (i_site != allocsites_relation.begin()) cout << ",";
		
		cout << "\n\t/* allocsite info for " << i_site->first.first << "+"
			<< std::hex << "0x" << i_site->first.second << std::dec << " */";
		cout << "\n\t{ (void*)0, (void*)0, "
			<< "(char*) " << "0" // will fix up at load time
			<< " + " << i_site->first.second << "UL, " 
			<< "&" << mangle_typename(i_site->second)
			<< " }";
	}
	// output a null terminator entry
	if (allocsites_relation.size() > 0) cout << ",";
	cout << "\n\t{ (void*)0, (void*)0, (void*)0, (struct rec *)0 }";
	
	// close the list
	cout << "\n};\n";
	
	return 0;
}	

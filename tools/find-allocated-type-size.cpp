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
using std::multimap;
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
using dwarf::tool::abstract_c_compiler;

int main(int argc, char **argv)
{
	/* We read from stdin lines such as those output by dumpallocs,
	 * prefixed by their filename. Actually they will have been 
	 * stored in .allocsites files. */ 
	
	using std::unique_ptr;
	unique_ptr<std::ifstream> p_objfile;
	unique_ptr<root_die> p_root;
	
	std::shared_ptr<ifstream> p_in;
	
	string fnname;
	if (argc < 2) 
	{
		cerr << "Please specify an allocation function name." << endl;
		return 1;
	}
	
	fnname = argv[1];
	
	for (int i = 2; i < argc; ++i)
	{
		// open this file's dwarf info
		auto p_in = new ifstream(argv[i]);
		if (!*p_in) 
		{
			cerr << "Could not open file " << argv[i] << endl;
		}
		else
		{
			root_die *p_root = new root_die(fileno(*p_in));

			// search the root for a function named fnname
			auto cus_seq = p_root->begin().children().subseq_of<compile_unit_die>();
			for (auto i_cu = cus_seq.first; i_cu != cus_seq.second; ++i_cu)
			{
				auto found = i_cu->named_child(fnname);
				if (found && found.is_a<subprogram_die>())
				{
					auto return_type = found.as_a<subprogram_die>()->get_type();

					if (return_type)
					{
						auto concrete_t = return_type->get_concrete_type();
						if (concrete_t && concrete_t.is_a<pointer_type_die>())
						{
							auto target_t = concrete_t.as_a<pointer_type_die>()->get_type();
							if (target_t && target_t->get_concrete_type())
							{
								auto opt_byte_sz = target_t->get_concrete_type()
									->calculate_byte_size();
								if (!opt_byte_sz)
								{
									cerr << "Warning: could not compute byte size of " 
										<< target_t << endl;
								}
								else
								{
									cout << *opt_byte_sz << "\t from " << found.as_a<core::basic_die>()->summary() << endl;
								}
							}
						}
						else cerr << "Warning: return type of " << found << " is not a pointer type "
							<< "(" << concrete_t << ")" << endl;
					} 
				}
			}

			/* HACK: don't delete right now, to work around bug in libdwarfpp. */
			// delete p_root;
		}
		
		// delete p_in;
	}

	return 0;
}

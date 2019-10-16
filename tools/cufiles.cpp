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
#include <srk31/algorithm.hpp>
#include <srk31/ordinal.hpp>
#include <fileno.hpp>
#include <dwarfpp/lib.hpp>

using std::cin;
using std::cout;
using std::cerr;
using std::map;
using std::string;
using std::ifstream;
using std::ostringstream;

using namespace dwarf;
using dwarf::core::root_die;
using dwarf::core::iterator_sibs;
using dwarf::core::compile_unit_die;

int debug_level;
int main(int argc, char **argv)
{
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
	
	if (getenv("CUFILES_DEBUG_LEVEL"))
	{
		debug_level = atoi(getenv("CUFILES_DEBUG_LEVEL"));
	}
	
	using core::root_die;
	int fd = fileno(infstream);
	dwarf::core::root_die root(fd);
		
	auto cus = root.begin().children();
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
				//if (!path(cu_srcfile_mayberelative).has_root_directory())
				if (cu_srcfile_mayberelative.length() > 0 && cu_srcfile_mayberelative.at(0) != '/')
				{
					current_sourcepath = cu_comp_dir + '/' + cu_srcfile_mayberelative;
				}
				else current_sourcepath = /*path(*/cu_srcfile_mayberelative/*)*/;

				cerr << "CU " << *i_cu->get_name() << " sourcefile " << i_srcfile << " is " <<
					cu_srcfile_mayberelative
					<< ", sourcepath "
					<< current_sourcepath
					<< endl;
			}
		}
	} // end for each CU

	/*
	HMM.
	So we can easily have things in our source files, e.g. printf,
	that are not described in the DWARF
	and whose defining header is also not referenced in the DWARF.

	Can we view this as a pathfinding exercise in a graph of #include files?

	Not really, because we don't know where to start looking.
	E.g. if printf came from blah/blah/blah.h, thanks to -Iblah/blah,
	we'd have no reference to that. In general we can't bootstrap the search
	using standard directories; the information on the command line is essential.
	So I think this is something that needs fixing in DWARF,
	maybe by not omitting entries for referenced things
	maybe by describing the #include paths explicitly,
	maybe by including a source file entry for all embodied headers,
		even if nothing in the info section uses them.
	BUT MAYBE we can hack around the lack of things,
	like printf, by some kind of type inference? i.e. analysis of the reference site?

	OR is there another way of looking at this?
	What information do we actually need?
	Allocation sites, sizeof, any macro definitions they depend on.
	sizeof is often used inside macros, so we really do need to
	do the preprocessing early.

	-fno-eliminate-unused-debug-types will include any header that defines a type.
	So it's not perfect but might be useful.

	Can we also infer the -I paths by looking at how the original
	#include directives were qualified?
	E.g. if we see #include <blah/blah.h> and we see
	/path/to/blah/blah.h
	embodied in the output, it seems likely that -I/path/to was on the command line.

	*/


	return 0;
}

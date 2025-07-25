#include <iostream>
#include <vector>
#include <string>
#include "uniqtypes.hpp"

using std::cout;
using std::cerr;
using std::vector;
using std::string;
using namespace allocs::tool;

static int debug_out = 1;

int main(int argc, char **argv)
{
	unsigned nfiles = argc - 1;
	if (nfiles < 1) 
	{
		cerr << "Please name an input file." << endl;
		exit(1);
	}

	vector<string> fnames;
	for (unsigned i = 0; i < nfiles; ++i)
	{
		string fname = argv[1+i];
		fnames.push_back(fname);
	}
	
	cout << "#include \"uniqtype-defs.h\"\n\n";
	return dump_usedtypes(fnames, cout, cerr, /* continue_on_error */ true);
}

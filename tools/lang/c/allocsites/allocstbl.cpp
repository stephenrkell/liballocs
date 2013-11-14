/* We read data in tab-separated allocs format, and output a table
 * mapping allocsites to uniqtypes. */
 
#include "helpers.hpp"

int main(int argc, char **argv)
{
	/* We read from stdin lines such as those output by dumpallocs,
	 * prefixed by their filename. Actually they will have been 
	 * stored in .allocsites files. */ 
	
	map<string, shared_ptr<ifstream> > ifstreams;
	map<string, shared_ptr<lib::file> > files;
	map<string, shared_ptr<lib::dieset> > diesets;
	
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
	
	char buf[4096];
	string objname;
	string symname;
	unsigned offset;
	string cuname; 
	unsigned line;
	string alloc_typename;
	while (in.getline(buf, sizeof buf - 1)
		&& 0 == read_allocs_line(string(buf), objname, symname, offset, cuname, line, alloc_typename))
	{
		/* For each line, we want to output a record mapping its 
		 * allocsite to its uniqtype rec. Unfortunately, allocsites
		 * are dependent on link addresses. We just use the C preprocessor
		 * to hack around this, for the moment */
	}
	
	return 0;
}	

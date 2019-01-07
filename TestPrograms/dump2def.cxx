// dump2def.cxx - Written and placed in public domain by Jeffrey Walton
//                Create a module definitions file from a dumpbin file/
//                dump2def can be used to create a list of exports from
//                a static library. Then, the exports can used to build
//                a dynamic link library with the same exports.

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <set>

typedef std::set<std::string> SymbolMap;

void PrintHelpAndExit(int code)
{
	std::cout << "dump2def - create a module definitions file from a dumpbin file" << std::endl;
	std::cout << "           Written and placed in public domain by Jeffrey Walton" << std::endl;
	std::cout << std::endl;

	std::cout << "Usage: " << std::endl;

	std::cout << "  dump2def <infile>" << std::endl;
	std::cout << "    - Create a def file from <infile> and write it to a file with" << std::endl;
	std::cout << "      the same name as <infile> but using the .def extension" << std::endl;

	std::cout << "  dump2def <infile> <outfile>" << std::endl;
	std::cout << "    - Create a def file from <infile> and write it to <outfile>" << std::endl;
	
	std::exit(code);
}

int main(int argc, char* argv[])
{
	// ******************** Handle Options ******************** //
	
	// Convenience item
	std::vector<std::string> opts;
	for (size_t i=0; i<argc; ++i)
		opts.push_back(argv[i]);

	// Look for help
	std::string opt = opts.size() < 3 ? "" : opts[1].substr(0,2);
	if (opt == "/h" || opt == "-h" || opt == "/?" || opt == "-?")
		PrintHelpAndExit(0);
	
	// Add <outfile> as needed
	if (opts.size() == 2)
	{
		std::string outfile = opts[1];
		std::string::size_type pos = outfile.length() < 5 ? std::string::npos : outfile.length() - 5;
		if (pos == std::string::npos || outfile.substr(pos) != ".dump")
			PrintHelpAndExit(1);
		
		outfile.replace(pos, 5, ".def");
		opts.push_back(outfile);
	}

	// Check or exit
	if (opts.size() != 3)
		PrintHelpAndExit(1);

	// ******************** Read MAP file ******************** //

	SymbolMap symbols;

	try
	{
		std::ifstream infile(opts[1].c_str());
		std::string::size_type pos;
		std::string line;

		// Find start of the symbol table
		while (std::getline(infile, line))
		{
			pos = line.find("public symbols");
			if (pos == std::string::npos) { continue; }		

			// Eat the whitespace after the table heading
			infile >> std::ws;
			break;
		}

		while (std::getline(infile, line))
		{
			// End of table
			if (line.empty()) { break; }

			std::istringstream iss(line);
			std::string address, symbol;
			iss >> address >> symbol;

			symbols.insert(symbol);
		}
	}
	catch (const std::exception& ex)
	{
		std::cerr << "Unexpected exception:" << std::endl;
		std::cerr << ex.what() << std::endl;
		std::cerr << std::endl;

		PrintHelpAndExit(1);
	}

	// ******************** Write DEF file ******************** //

	try
	{
		std::ofstream outfile(opts[2].c_str());

		// Library name, cryptopp.dll
		std::string name = opts[2];
		std::string::size_type pos = name.find_last_of(".");

		if (pos != std::string::npos)
			name.erase(pos);

		outfile << "LIBRARY " << name << std::endl;
		outfile << "DESCRIPTION \"Crypto++ Library\"" << std::endl;		
		outfile << "EXPORTS" << std::endl;
		outfile << std::endl;

		outfile << "\t;; " << symbols.size() << " symbols" << std::endl;

		// Symbols from our object files
		SymbolMap::const_iterator it = symbols.begin();
		for ( ; it != symbols.end(); ++it)
			outfile << "\t" << *it << std::endl;
	}
	catch (const std::exception& ex)
	{
		std::cerr << "Unexpected exception:" << std::endl;
		std::cerr << ex.what() << std::endl;
		std::cerr << std::endl;

		PrintHelpAndExit(1);
	}

	std::cout << std::endl;
	std::cout << symbols.size() << " library symbols";
	std::cout << std::endl;

	return 0;
}

#include <iostream>
#include <fstream>

using namespace std;

int main(int argc, const char * argv []) {
	ofstream fout(argv[1]);
	fout << "This is a test" << endl;
	fout << "This is only a test" << endl;
	return 0;
}

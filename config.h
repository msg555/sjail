#ifndef __CONFIG_H
#define __CONFIG_H

#include <iostream>
#include <sstream>
#include <sys/resource.h> 

#ifndef NDEBUG
#define DEBUG(x) cerr << x << endl
#else
#define DEBUG(x)
#endif

#define TIME_NO_LIMIT 0
#define MEM_NO_LIMIT 0
#define FILE_NO_LIMIT 0

#define REGISTER_FLAG(FLAG_NAME, ALLOW_SHORT, TYPE, DEFAULT, DESCRIPTION) \
  TYPE get_ ## FLAG_NAME (); \
  void set_ ## FLAG_NAME (const TYPE &);
#include "flags.h"
#undef REGISTER_FLAG

template<class A, class B>
A convert(const B & x, const A & d = A()) {
	std::stringstream ss;
	ss << x;
	A r = d;
	ss >> r;
	return r;
}

// Prints usage information.
void print_usage(const char* argv0);

// Parses the file indicated by file.  Returns true on success.
bool parse_file(const char* file);

// Parses the arguments passed by command line.  Returns -1 on error.
int parse_arguments(int argc, char** argv);

#endif

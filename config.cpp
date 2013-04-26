#include <iostream>
#include <fstream>
#include <string>
#include <stdlib.h>
#include <string.h>

#include "config.h"

using namespace std;

#define REGISTER_FLAG(FLAG_NAME, ALLOW_SHORT, TYPE, DEFAULT, DESCRIPTION) \
  TYPE flag_ ## FLAG_NAME = DEFAULT; \
  TYPE get_ ## FLAG_NAME () { return flag_ ## FLAG_NAME; } \
  void set_ ## FLAG_NAME (const TYPE & val) { flag_ ## FLAG_NAME = val; }
#include "flags.h"
#undef REGISTER_FLAG

void print_usage(const char* argv0) {
  printf("Usage: %s [options] prog-and-args\n", argv0);
  printf("Options:\n");

  size_t max_width = 59;
  #define REGISTER_FLAG(FLAG_NAME, ALLOW_SHORT, TYPE, DEFAULT, DESCRIPTION)   \
    do {                                                                      \
      printf("    ");                                                         \
      if(ALLOW_SHORT) {                                                       \
        printf("-%c --%-10s: ", *#FLAG_NAME, #FLAG_NAME);                     \
      } else {                                                                \
        printf("--%-13s: ", #FLAG_NAME);                                      \
      }                                                                       \
      const char* desc = DESCRIPTION;                                         \
      const char* desc_end = desc, *i;                                        \
      for(desc_end = desc; *desc_end; desc = desc_end) {                      \
        for(desc_end = desc + max_width, i = desc;                            \
            *i && i != desc + max_width; ++i) {                               \
          if(*i == ' ') {                                                     \
            desc_end = i;                                                     \
          }                                                                   \
        }                                                                     \
        if(!*i) {                                                             \
          desc_end = i;                                                       \
        }                                                                     \
        printf("%s\n", string(desc, desc_end - desc).c_str());                \
        if(*desc_end == ' ') {                                                \
          ++desc_end;                                                         \
        }                                                                     \
        if(*desc_end) {                                                       \
          printf("%s", string(21, ' ').c_str());                              \
        }                                                                     \
      }                                                                       \
    } while(0);
  #define FLAG_SECTION(SECTION_NAME)                                          \
    do {                                                                      \
      printf("\n  " SECTION_NAME "\n");                                       \
    } while(0);
  #include "flags.h"
  #undef FLAG_SECTION
  #undef REGISTER_FLAG
}

bool parse_file(const char * file) {
  ifstream fin(file);
  if(fin.fail()) {
    return false;
  }
  
	string ln;
  while(getline(fin, ln)) {
		istringstream sin(ln);
		string key, value;
		if(sin >> key) {
      if(!(sin >> value)) {
        value = "1";
      }
      if(key[0] == '#')
        continue;

      #define REGISTER_FLAG(FLAG_NAME, ALLOW_SHORT, TYPE, DEFAULT, DESCRIPTION) \
        if(key == #FLAG_NAME) { \
          set_ ## FLAG_NAME (convert(value, get_ ## FLAG_NAME ())); \
          continue; \
        }
      #include "flags.h"
      #undef REGISTER_FLAG

      cerr << "Error: unrecognized key " << key << " in " << file << endl;
      exit(1);
    }
	}

  return true;
}

int parse_arguments(int argc, char** argv) {
  int p;
	for(p = 1; p < argc && argv[p][0] == '-'; p++) {
    if(argv[p][1] == '-') {
      #define REGISTER_FLAG(FLAG_NAME, ALLOW_SHORT, TYPE, DEFAULT, DESCRIPTION) \
        if(string(#FLAG_NAME) == argv[p] + 2) { \
          if(string("bool") == #TYPE) { \
            set_ ## FLAG_NAME (convert< TYPE >(1)); \
          } else if(++p >= argc) { \
            cerr << "Error: expected value after " << #FLAG_NAME << " switch" << endl; \
            return argc; \
          } else { \
            set_ ## FLAG_NAME (convert(argv[p], get_ ## FLAG_NAME ())); \
          } \
          continue; \
        }
      #include "flags.h"
      #undef REGISTER_FLAG
      cerr << "Error: unrecognized flag " << argv[p] + 2 << endl;
      exit(1);
    } else for(const char * ch = argv[p] + 1; *ch; ch++) {
      #define REGISTER_FLAG(FLAG_NAME, ALLOW_SHORT, TYPE, DEFAULT, DESCRIPTION) \
        if(ALLOW_SHORT && *ch == * #FLAG_NAME) { \
          if(string("bool") == #TYPE) \
            set_ ## FLAG_NAME (convert< TYPE >(1)); \
          else if(++p >= argc) { \
            cerr << "Error: expected value after " << #FLAG_NAME << " switch" << endl; \
            return argc; \
          } else \
            set_ ## FLAG_NAME (convert(argv[p], get_ ## FLAG_NAME ())); \
          continue; \
        }
      #include "flags.h"
      #undef REGISTER_FLAG
      cerr << "Error: unrecognized switch " << *ch << endl;
      exit(1);
		}
	}
	return p;
}

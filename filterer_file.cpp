#include <regex.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/limits.h>

#include "report.h"
#include "config.h"
#include "filterer.h"

bool is_file_allowed(string file) {
    string s = get_files();
    if(s != "") {
        regex_t r;
        if(regcomp(&r, s.c_str(), REG_EXTENDED | REG_NOSUB)) {
            log_violation("failed to compile file regexp");
        } else if(!regexec(&r, file.c_str(), (size_t)0, NULL, 0)) {
            regfree(&r);
            return true;
        }
    }
    return false;
}

bool process_fileopen(unsigned long param1, unsigned long param2, int pid) {
    char *ret;
    char fullpath[PATH_MAX], file[PATH_MAX];
   
    if(!read_from_pid_to_null(file, param1, PATH_MAX, pid)) {
        return false;
    }

    ret = realpath(file, fullpath);
    if(ret != fullpath && get_rdonly()) {
        log_violation("Could not find file: " + string(file));
        return false;
    }

    if(!is_file_allowed(string(fullpath))) {
        log_violation("Attempt to access restricted file: " + string(file));
        return false;
    }

    if(get_rdonly() && (param2 ^ O_RDONLY)) {
        log_violation("Opened file for write");
        return false;
    }

    return true;
}



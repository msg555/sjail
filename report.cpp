#include <iostream>
#include <vector>
#include <cstdlib>
#include <cstdio>

#include "sjail.h"
#include "config.h"
#include "process_state.h"
#include "signal_tab.h"
#include "report.h"

/* TODO(msg555): For the JSON stuff we may need to escape some of the strings.
 */

static FILE* fout = NULL;

bool init_report() {
  if(!get_report()) {
    return true;
  }
  fout = fopen(get_report_file().c_str(), "w");
  if(!fout) {
    return false;
  }
  if(get_json()) {
    fprintf(fout, "[\n");
  }
  return true;
}

bool finalize_report() {
  if(!fout) {
    return true;
  } else if(get_json()) {
    fprintf(fout, "]\n");
  }
  return !fclose(fout);
}

void log_create(pid_t pid, pid_t ppid, enum create_type type) {
  if(!fout) {
    return;
  } else if(get_json()) {
    fprintf(fout, "\t{\n");
    fprintf(fout, "\t\t\"pid\": %d,\n", pid);
    fprintf(fout, "\t\t\"type\": \"create\",\n");
    if(type != CREATE_ROOT) {
      fprintf(fout, "\t\t\"parent_pid\": %d,\n", ppid);
      if(type == CREATE_FORK) {
        fprintf(fout, "\t\t\"fork\": true\n");
      } else {
        fprintf(fout, "\t\t\"clone\": true\n");
      }
    }
    fprintf(fout, "\t},\n");
  } else {
    if(type == CREATE_ROOT) {
      fprintf(fout, "%d:root_process\n", pid);
    } else {
      fprintf(fout, "%d:%s_parent:%d\n", pid,
              type == CREATE_FORK ? "fork" : "clone", ppid);
    }
  }
  fflush(fout);
}

void log_exit(pid_t pid, const exit_data& data, bool final) {
  const rusage* res = data.resources;
  if(!fout) {
    return;
  } else if(get_json()) {
    fprintf(fout, "\t{\n");
    fprintf(fout, "\t\t\"pid\": %d,\n", pid);
    fprintf(fout, "\t\t\"type\": \"exit\",\n");
    fprintf(fout, "\t\t\"time_user_us\": %lld,\n",
            res->ru_utime.tv_sec * 1000000LL + res->ru_utime.tv_usec);
    fprintf(fout, "\t\t\"time_sys_us\": %lld,\n",
            res->ru_stime.tv_sec * 1000000LL + res->ru_stime.tv_usec);
    fprintf(fout, "\t\t\"time_wall_us\": %llu,\n", data.wall_time_us);
    fprintf(fout, "\t\t\"max_rss_kb\": %ld,\n", res->ru_maxrss);
    fprintf(fout, "\t\t\"max_mapped_kb\": %lu,\n",
            data.max_mapped_bytes / 1024);
    switch(data.type) {
      case EXIT_STATUS:
        fprintf(fout, "\t\t\"status\": %d\n", data.status);
        break;
      case EXIT_SIGNAL:
        fprintf(fout, "\t\t\"signal\": \"%s\"\n",
                get_signal_name(data.signum).c_str());
        break;
      case EXIT_KILLED:
        fprintf(fout, "\t\t\"killed\": true\n");
        break;
    }
    fprintf(fout, final ? "\t}\n" : "\t},\n");
  } else {
    fprintf(fout, "%d:user_time_sec:%ld.%06ld\n", pid,
            res->ru_utime.tv_sec, res->ru_utime.tv_usec);
    fprintf(fout, "%d:system_time_sec:%ld.%06ld\n", pid,
            res->ru_stime.tv_sec, res->ru_stime.tv_usec);
    fprintf(fout, "%d:wall_time_sec:%llu.%06llu\n", pid,
            data.wall_time_us / 1000000, data.wall_time_us % 1000000);
    fprintf(fout, "%d:max_rss_kb:%ld\n", pid, res->ru_maxrss);
    fprintf(fout, "%d:max_mapped_kb:%lu\n", pid, data.max_mapped_bytes / 1024);
    switch(data.type) {
      case EXIT_STATUS:
        fprintf(fout, "%d:status:%d\n", pid, data.status);
        break;
      case EXIT_SIGNAL:
        fprintf(fout, "%d:term_signal:%s\n", pid,
                get_signal_name(data.signum).c_str());
        break;
      case EXIT_KILLED:
        fprintf(fout, "%d:killed\n", pid);
        break;
    }
  }
  fflush(fout);
}

void log_blocked_syscall(process_state& st) {
  enum SYSCALL sys = st.get_syscall();
  if(!fout) {
    return;
  } else if(get_json()) {
    fprintf(fout, "\t{\n");
    fprintf(fout, "\t\t\"pid\": %d,\n", st.get_pid());
    fprintf(fout, "\t\t\"type\": \"block\",\n");
    fprintf(fout, "\t\t\"syscall\": \"%s\",\n", st.get_syscall_name(sys));
    fprintf(fout, "\t\t\"params\": [\n");
    for(size_t i = 0, j = st.get_num_params(sys); i != j; i++) {
      fprintf(fout, "\t\t\t%lu%s\n", st.get_param(i), i + 1 == j ? "" : ",");
    }
    fprintf(fout, "\t\t]\n");
    fprintf(fout, "\t},\n");
  } else {
    fprintf(fout, "%d:syscall:%s(%lu,%lu,%lu,%lu,%lu,%lu)\n",
            st.get_pid(), st.get_syscall_name(sys),
            st.get_param(0), st.get_param(1), st.get_param(2),
            st.get_param(3), st.get_param(4), st.get_param(5));
  }
  fflush(fout);
}

void log_violation(pid_t pid, const std::string& message) {
  if(!fout) {
    return;
  } else if(get_json()) {
    fprintf(fout, "\t{\n");
    fprintf(fout, "\t\t\"pid\": %d,\n", pid);
    fprintf(fout, "\t\t\"type\": \"violation\",\n");
    fprintf(fout, "\t\t\"message\": \"%s\"\n", message.c_str());
    fprintf(fout, "\t},\n");
  } else {
    fprintf(fout, "%d:violation:%s\n", pid, message.c_str());
  }
  fflush(fout);
}

void log_error(pid_t pid, const std::string& message) {
  if(!fout) {
    return;
  } else if(get_json()) {
    fprintf(fout, "\t{\n");
    fprintf(fout, "\t\t\"pid\": %d,\n", pid);
    fprintf(fout, "\t\t\"type\": \"error\",\n");
    fprintf(fout, "\t\t\"message\": \"%s\"\n", message.c_str());
    fprintf(fout, "\t},\n");
  } else {
    fprintf(fout, "%d:error:%s\n", pid, message.c_str());
  }
  fflush(fout);
}

void log_info(pid_t pid, int level, const std::string& message) {
  if(!fout || level > get_log_level()) {
    return;
  } else if(get_json()) {
    fprintf(fout, "\t{\n");
    fprintf(fout, "\t\t\"pid\": %d,\n", pid);
    fprintf(fout, "\t\t\"type\": \"log\",\n");
    fprintf(fout, "\t\t\"level\": %d,\n", level);
    fprintf(fout, "\t\t\"message\": \"%s\"\n", message.c_str());
    fprintf(fout, "\t},\n");
  } else {
    fprintf(fout, "%d:log(%d):%s\n", pid, level, message.c_str());
  }
  fflush(fout);
}

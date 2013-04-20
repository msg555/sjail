#ifdef FLAG_SECTION
FLAG_SECTION("General")
#endif
REGISTER_FLAG(help, 0, bool, false,
              "Displays this message.")
REGISTER_FLAG(passive, 1, bool, false,
              "Only monitor jailed program.  Do not block any system calls. "
              "Does not affect flags in resources section")
REGISTER_FLAG(conf_file, 1, std::string, "jail.conf",
              "Read in configuration key value pairs from file. "
              "Default is jail.conf")
REGISTER_FLAG(no_conf, 0, bool, false,
              "Only take configuration through the command line.  Ignores the "
              "conf_file flag and default jail.conf file")

#ifdef FLAG_SECTION
FLAG_SECTION("Processes")
#endif
REGISTER_FLAG(processes, 0, int, 0, "Global limit on additional process creation. "
              "Negative limits indicate no limit. Default is 0.");
REGISTER_FLAG(threads, 0, int, 0, "Global limit on additional thread creation. "
              "Negative limits indicate no limit. Default is 0.");
REGISTER_FLAG(exec_match, 0, std::string, "", "Valid filenames to pass to "
              "exec.  An empty string is default and interpreted as "
              "disabling exec.");

#ifdef FLAG_SECTION
FLAG_SECTION("Resources")
#endif
REGISTER_FLAG(time, 1, rlim_t, TIME_NO_LIMIT,
              "The allowed runtime of the program. Default is no limit.")
REGISTER_FLAG(mem, 1, rlim_t, MEM_NO_LIMIT,
              "The allowed memory limit of the program in KB. "
              "Default is no limit.")
REGISTER_FLAG(file_limit, 0, rlim_t, FILE_NO_LIMIT,
              "The allowed file size limit of the program. Default is no limit.")
REGISTER_FLAG(cwd, 0, std::string, "", "Working directory of client "
              "application. This is called prior to any root changes.")
REGISTER_FLAG(chroot, 0, std::string, "",
              "Path to set as root. Jail must be run as root to use this, "
              "therefore this flag should typically be coupled with "
              "user/group flags.")
REGISTER_FLAG(user, 1, std::string, "", "User to switch to.")
REGISTER_FLAG(group, 1, std::string, "", "Group to switch to.")

#ifdef FLAG_SECTION
FLAG_SECTION("Network options")
#endif
REGISTER_FLAG(net, 1, bool, false, "Enables network access.")
REGISTER_FLAG(tcp, 0, bool, false, "Allows tcp network access. Requires --net.")
REGISTER_FLAG(udp, 0, bool, false, "Allows udp network access. Requires --net.")
REGISTER_FLAG(listen, 0, bool, false, "Allows program to bind to a port. "
              "Requires --net.")
REGISTER_FLAG(net_regexp, 0, std::string, "", "Restricts tcp connections and "
              "udp outgoing packets to those where "
              "\"ip;port;{INET,INET6,UNIX}\" "
              "matches the given regexp.  Default is blank (match anything)")

#ifdef FLAG_SECTION
FLAG_SECTION("File options")
#endif
REGISTER_FLAG(files, 1, std::string, "", "Enable file read/write access to the "
              "comma separated list of regexps")
REGISTER_FLAG(rdonly, 0, bool, false, "Restrict file access to read only. "
              "Requires --files [regexp]")

#ifdef FLAG_SECTION
FLAG_SECTION("Reporting")
#endif
REGISTER_FLAG(report, 1, bool, false, "Enables report generation.")
REGISTER_FLAG(report_file, 0, std::string, "jail.out", "Sets the report file "
              "name. Default is jail.out.")
REGISTER_FLAG(log_level, 1, int, 1, "Sets the logging level.  Level 5 gives "
              "everything.  Default is 1")

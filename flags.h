#ifdef FLAG_SECTION
FLAG_SECTION("General")
#endif
REGISTER_FLAG(help, 0, bool, false, "Displays this message.")
REGISTER_FLAG(passive, 1, bool, false, "Only monitor jailed program.  Do not block any system calls.")
REGISTER_FLAG(conf_file, 1, string, "jail.conf", "Read in configuration key value pairs from file.  Default is jail.conf")

#ifdef FLAG_SECTION
FLAG_SECTION("Resources")
#endif
REGISTER_FLAG(time, 1, int, TIME_NO_LIMIT, "The allowed runtime of the program.  Default is no limit.")
REGISTER_FLAG(mem, 1, int, MEM_NO_LIMIT, "The allowed memory limit of the program.  Default is no limit.")

#ifdef FLAG_SECTION
FLAG_SECTION("Network options")
#endif
REGISTER_FLAG(net, 1, bool, false, "Enables network access.")
REGISTER_FLAG(tcp, 0, bool, false, "Allows tcp network access.  Requires --net.")
REGISTER_FLAG(udp, 0, bool, false, "Allows udp network access.  Requires --net.")
REGISTER_FLAG(listen, 0, bool, false, "Allows program to bind to a port.  Requires --net.")
REGISTER_FLAG(net_regexp, 0, string, "", "Restricts tcp connections and udp outgoing packets to those where \"ip;port;{INET,INET6,UNIX}\" matches the given regexp.  Default is blank (match anything)")

#ifdef FLAG_SECTION
FLAG_SECTION("File options")
#endif
REGISTER_FLAG(files, 1, string, "", "Enable file read/write access to the comma separated list of regexps")
REGISTER_FLAG(rdonly, 0, bool, false, "Restrict file access to read only.  Requires --files [regexp]")

#ifdef FLAG_SECTION
FLAG_SECTION("Reporting")
#endif
REGISTER_FLAG(report, 1, bool, false, "Enables report generation.")
REGISTER_FLAG(report_file, 0, string, "jail.out", "Sets the report file name.  Default is jail.out.")
REGISTER_FLAG(log_level, 1, int, 1, "Sets the logging level.  Level 5 gives everything.  Default is 1")


/* SPDX-License-Identifier: AGPL-3.0-or-later */
/*
 * Soft:        The main goal of gtp-guard is to provide robust and secure
 *              extensions to GTP protocol (GPRS Tunneling Procol). GTP is
 *              widely used for data-plane in mobile core-network. gtp-guard
 *              implements a set of 3 main frameworks:
 *              A Proxy feature for data-plane tweaking, a Routing facility
 *              to inter-connect and a Firewall feature for filtering,
 *              rewriting and redirecting.
 *
 * Authors:     Alexandre Cassen, <acassen@gmail.com>
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU Affero General Public
 *              License Version 3.0 as published by the Free Software Foundation;
 *              either version 3.0 of the License, or (at your option) any later
 *              version.
 *
 * Copyright (C) 2023-2026 Alexandre Cassen, <acassen@gmail.com>
 */

#include <unistd.h>
#include <getopt.h>
#include <sys/resource.h>

#include "gtp_data.h"
#include "gtp_netlink.h"
#include "gtp_bpf_capture.h"
#include "gtp_conn.h"
#include "gtp_teid.h"
#include "gtp_session.h"
#include "gtp_vty_shell.h"
#include "command.h"
#include "bitops.h"
#include "signals.h"
#include "pidfile.h"
#include "utils.h"
#include "logger.h"
#include "memory.h"
#include "config.h"
#include "libbpf.h"
#include "main.h"

/* local variables */
static char *pid_file = PROG_PID_FILE;
static struct log_options log_opt = {
	.timestamp = LOG_TS_SHORT,
};

/* Daemon stop sequence */
static void
stop_gtp(void)
{
	log_message(LOG_INFO, "Stopping " VERSION_STRING);

	/* Just cleanup memory & exit */
	vty_terminate();
	cmd_terminate();
	gtp_netlink_destroy();
	free_daemon_data();
	thread_destroy_master(master);

#ifdef _DEBUG_
	memory_free_final("gtp-guard process");
#endif
	closelog();
	pidfile_rm(pid_file);
	exit(EXIT_SUCCESS);
}

/* Daemon init sequence */
static void
start_gtp(void)
{
	int ret;

	/* Configuration file parsing */
	daemon_data = alloc_daemon_data();

	gtp_netlink_init();
	cmd_init();
	vty_init();
	sort_node();
	gtp_conn_module_init();
	gtp_teid_init();
	gtp_sessions_init();

	ret = vty_read_config(conf_file, default_conf_file);
	if (ret < 0)
		stop_gtp();
}

/* Terminate handler */
static void
sigend(__attribute__((unused)) void *v, __attribute__((unused)) int sig)
{
	__set_bit(GTP_FL_STOP_BIT, &daemon_data->flags);
	thread_add_terminate_event(master);
}

/* Initialize signal handler */
void
signal_init(void)
{
	signal_set(SIGHUP, sigend, NULL);
	signal_set(SIGINT, sigend, NULL);
	signal_set(SIGTERM, sigend, NULL);
	signal_noignore_sigchld();
	signal_ignore(SIGPIPE);
}

/* Usage function */
static void
usage(const char *prog)
{
	fprintf(stderr, VERSION_STRING "\n");
	fprintf(stderr, COPYRIGHT_STRING "\n");
	fprintf(stderr, "libbpf %s\n", libbpf_version_string());
	fprintf(stderr,
		"\nUsage:\n"
		"  %s\n"
		"  %s -f gtp-guard.conf\n"
		"  %s -d -t long -b\n"
		"  %s -h\n"
		"  %s -v\n\n", prog, prog, prog, prog, prog);
	fprintf(stderr,
		"Commands:\n"
		"Either long or short options are allowed.\n"
		"  %s --vty-shell/--cli    -V    Open VTY Shell with local daemon.\n"
		"  %s --use-file           -f    Use the specified configuration file.\n"
		"                                Default is /etc/gtp-guard/gtp-guard.conf.\n"
		"  %s --enable-bpf-debug   -b    Enable verbose libbpf log debug.\n"
		"  %s --log-debug          -d    Enable LOG_DEBUG.\n"
		"  %s --log-ts-fmt         -t    Console log timestamp fmt [short,long,none].\n"
		"  %s --help               -h    Display this short inlined help screen.\n"
		"  %s --version            -v    Display the version number\n",
		prog, prog, prog, prog, prog, prog, prog);
}

/* Command line parser */
static void
parse_cmdline(int argc, char **argv)
{
	int c, longindex, curind;
	bool bad_option = false;

	struct option long_options[] = {
		{"log-debug",		no_argument,		NULL, 'd'},
		{"log-ts-fmt",		required_argument,	NULL, 't'},
		{"enable-bpf-debug",	no_argument,		NULL, 'b'},
		{"use-file",		required_argument,	NULL, 'f'},
		{"vty-shell",		optional_argument,	NULL, 'V'},
		{"cli",			optional_argument,	NULL, 'V'},
		{"version",		no_argument,		NULL, 'v'},
		{"help",		no_argument,		NULL, 'h'},
		{NULL,			0,			NULL,  0 }
	};

	/* VTY Shell. force default value for login Shell */
	if (argv[0][0] == '-')
		exit(gtp_vtysh(VTY_UNIX_PATH));

	curind = optind;
	while (longindex = -1, (c = getopt_long(argc, argv, ":dt:bf:V::vh",
						long_options, &longindex)) != -1) {
		if (longindex >= 0 &&
		    long_options[longindex].has_arg == required_argument &&
		    optarg && !optarg[0]) {
			c = ':';
			optarg = NULL;
		}

		switch (c) {
		case 'v':
			fprintf(stderr, VERSION_STRING "\n");
			fprintf(stderr, "libbpf %s\n", libbpf_version_string());
			exit(EXIT_SUCCESS);
			break;
		case 'h':
			usage(argv[0]);
			exit(EXIT_SUCCESS);
			break;
		case 't':
			if (!strcmp(optarg, "short"))
				log_opt.timestamp = LOG_TS_SHORT;
			else if (!strcmp(optarg, "long"))
				log_opt.timestamp = LOG_TS_LONG;
			else
				log_opt.timestamp = LOG_TS_NONE;
			break;
		case 'd':
			debug |= 8;
			log_opt.debug = true;
			break;
		case 'b':
			debug |= 16;
			break;
		case 'f':
			conf_file = optarg;
			break;
		case 'V':
			vty_shell_file = optarg;
			exit(gtp_vtysh(vty_shell_file ? : VTY_UNIX_PATH));
			break;
		case '?':
			if (optopt && argv[curind][1] != '-')
				fprintf(stderr, "Unknown option -%c\n", optopt);
			else
				fprintf(stderr, "Unknown option --%s\n", argv[curind]);
			bad_option = true;
			break;
		case ':':
			if (optopt && argv[curind][1] != '-')
				fprintf(stderr, "Missing parameter for option -%c\n", optopt);
			else
				fprintf(stderr, "Missing parameter for option --%s\n", long_options[longindex].name);
			bad_option = true;
			break;
		default:
			fprintf(stderr, "Unexpected option: '%c'\n", c);
			exit(EXIT_FAILURE);
			break;
		}
		curind = optind;
	}


	if (optind < argc) {
		fprintf(stderr, "Unexpected argument(s): ");
		while (optind < argc)
			fprintf(stderr, "%s ", argv[optind++]);
		fprintf(stderr, "\n");
	}

	if (bad_option)
		exit(EXIT_FAILURE);
}

/* Entry point */
int
main(int argc, char **argv)
{
	struct rlimit limit;

	/* Init debugging level */
	mem_allocated = 0;
	debug = 0;

	/* Parse command line and set debug level.
	 * bits 0..7 reserved by main.c
	 */
	parse_cmdline(argc, argv);

	/* Init logger library */
	log_opt.sd_prefix = !isatty(STDERR_FILENO);
	log_opt.color = !log_opt.sd_prefix && !getenv("NO_COLOR");
	log_set_options(&log_opt);

	log_info("Starting " VERSION_STRING);

	if (getenv("GTP_GUARD_PID_FILE"))
		pid_file = getenv("GTP_GUARD_PID_FILE");

	/* Check if gtp-guard is already running */
	if (process_running(pid_file)) {
		log_message(LOG_INFO, "daemon is already running");
		goto end;
	}

	/* write the pidfile */
	if (!pidfile_write(pid_file, getpid()))
		goto end;

	/* Increase maximum fd limit */
	getrlimit(RLIMIT_NOFILE, &limit);
	limit.rlim_max = limit.rlim_cur = 8192;
	setrlimit(RLIMIT_NOFILE, &limit);

	/* Create the master thread */
	master = thread_make_master(false);

	/* Signal handling initialization  */
	signal_init();

	/* Init daemon */
	start_gtp();

	/* Launch the scheduling I/O multiplexer */
	launch_thread_scheduler(master);

	/* Finish daemon process */
	stop_gtp();

	/*
	 * Reached when terminate signal catched.
	 * finally return from system
	 */
 end:
	closelog();
	exit(EXIT_SUCCESS);
}

#ifndef __LIB_SECEX_PROBE_STRUCT_H
#define __LIB_SECEX_PROBE_STRUCT_H

#include <linux/seccomp_ex.h>

struct probe_note {
	const char *provider;
	const char *name;
	const char *args;
	long loc_addr;
	long base_addr;
	long sema_addr;
};

struct probe_target {
	long abs_ip;
	long rel_ip;
	long sema_off;
	struct probe_spec spec;
	const char *spec_str;
};

#endif
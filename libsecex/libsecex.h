#ifndef __LIB_SECEX_H
#define __LIB_SECEX_H

#include "probe_struct.h"

int secex_open();
int secex_init(int fd, pid_t pid);
int secex_find_probe(pid_t pid, const char* path, const char *probe_provider, const char *probe_name, struct probe_target **out_targets, size_t *out_target_cnt);
int secex_enable_probe(struct probe_target *target, pid_t pid, const char* binary_path);
int secex_set_probe_spec(int fd, struct secex_probe_ctx *ctx);
#endif
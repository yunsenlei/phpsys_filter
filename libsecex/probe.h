#ifndef __LIB_SECEX_PROBE_H
#define __LIB_SECEX_PROBE_H

#include "probe_struct.h"

#define BASE_SEC ".stapsdt.base"
#define SEMA_SEC ".probes"
#define NOTE_SEC  ".note.stapsdt"
#define NOTE_NAME "stapsdt"
#define NOTE_TYPE 3


int collect_probe_targets(Elf *elf, const char *path, pid_t pid,
				const char *usdt_provider, const char *usdt_name,
				struct probe_target **out_targets, size_t *out_target_cnt);

#endif
#ifndef __LIB_SECEX_ELF_H
#define __LIB_SECEX_ELF_H

#include <stdbool.h>
#include <libelf.h>
#include <gelf.h>
struct elf_seg {
	long start;
	long end;
	long offset;
	bool is_exec;
};

int find_elf_sec_by_name(Elf *elf, const char *sec_name, GElf_Shdr *shdr, Elf_Scn **scn);
int parse_elf_segs(Elf *elf, const char *path, struct elf_seg **segs, size_t *seg_cnt);
struct elf_seg *find_elf_seg(struct elf_seg *segs, size_t seg_cnt, long virtaddr);
int parse_vma_segs(int pid, const char *lib_path, struct elf_seg **segs, size_t *seg_cnt);
struct elf_seg *find_vma_seg(struct elf_seg *segs, size_t seg_cnt, long offset);
#endif
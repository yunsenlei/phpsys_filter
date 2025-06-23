#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <libelf.h>
#include <gelf.h>

#include "elf.h"
#include "common.h"

static inline void secex_strlcpy(char *dst, const char *src, size_t sz)
{
	size_t i;

	if (sz == 0)
		return;

	sz--;
	for (i = 0; i < sz && src[i]; i++)
		dst[i] = src[i];
	dst[i] = '\0';
}


int find_elf_sec_by_name(Elf *elf, const char *sec_name, GElf_Shdr *shdr, Elf_Scn **scn)
{
	Elf_Scn *sec = NULL;
	size_t shstrndx;

	if (elf_getshdrstrndx(elf, &shstrndx))
		return -EINVAL;

	/* check if ELF is corrupted and avoid calling elf_strptr if yes */
	if (!elf_rawdata(elf_getscn(elf, shstrndx), NULL))
		return -EINVAL;

	while ((sec = elf_nextscn(elf, sec)) != NULL) {
		char *name;

		if (!gelf_getshdr(sec, shdr))
			return -EINVAL;

		name = elf_strptr(elf, shstrndx, shdr->sh_name);
		if (name && strcmp(sec_name, name) == 0) {
			*scn = sec;
			return 0;
		}
	}

	return -ENOENT;
}

struct elf_seg *find_elf_seg(struct elf_seg *segs, size_t seg_cnt, long virtaddr)
{
	struct elf_seg *seg;
	size_t i;

	/* for ELF binaries (both executables and shared libraries), we are
	 * given virtual address (absolute for executables, relative for
	 * libraries) which should match address range of [seg_start, seg_end)
	 */
	for (i = 0, seg = segs; i < seg_cnt; i++, seg++) {
		if (seg->start <= virtaddr && virtaddr < seg->end)
			return seg;
	}
	return NULL;
}

static int cmp_elf_segs(const void *_a, const void *_b)
{
	const struct elf_seg *a = _a;
	const struct elf_seg *b = _b;

	return a->start < b->start ? -1 : 1;
}

int parse_elf_segs(Elf *elf, const char *path, struct elf_seg **segs, size_t *seg_cnt)
{
	GElf_Phdr phdr;
	size_t i, n;
	int err;
	struct elf_seg *seg;
	void *tmp;

	*seg_cnt = 0;

	if (elf_getphdrnum(elf, &n)) {
		err = -errno;
		return err;
	}

	for (i = 0; i < n; i++) {
		if (!gelf_getphdr(elf, i, &phdr)) {
			err = -errno;
			return err;
		}

		// fprintf(stdout, "usdt: discovered PHDR #%d in '%s': vaddr 0x%lx memsz 0x%lx offset 0x%lx type 0x%lx flags 0x%lx\n",
		// 	 i, path, (long)phdr.p_vaddr, (long)phdr.p_memsz, (long)phdr.p_offset,
		// 	 (long)phdr.p_type, (long)phdr.p_flags);
		if (phdr.p_type != PT_LOAD)
			continue;

		tmp = secex_reallocarray(*segs, *seg_cnt + 1, sizeof(**segs));
		if (!tmp)
			return -ENOMEM;

		*segs = tmp;
		seg = *segs + *seg_cnt;
		(*seg_cnt)++;

		seg->start = phdr.p_vaddr;
		seg->end = phdr.p_vaddr + phdr.p_memsz;
		seg->offset = phdr.p_offset;
		seg->is_exec = phdr.p_flags & PF_X;
	}

	if (*seg_cnt == 0) {
		fprintf(stderr, "failed to find PT_LOAD program headers in '%s'\n", path);
		return -ESRCH;
	}

	qsort(*segs, *seg_cnt, sizeof(**segs), cmp_elf_segs);
	return 0;
}

int parse_vma_segs(int pid, const char *lib_path, struct elf_seg **segs, size_t *seg_cnt)
{
	char path[4096], line[4096], mode[16];
	size_t seg_start, seg_end, seg_off;
	struct elf_seg *seg;
	int tmp_pid, i, err;
	FILE *f;

	*seg_cnt = 0;

	/* Handle containerized binaries only accessible from
	 * /proc/<pid>/root/<path>. They will be reported as just /<path> in
	 * /proc/<pid>/maps.
	 */
	if (sscanf(lib_path, "/proc/%d/root%s", &tmp_pid, path) == 2 && pid == tmp_pid)
		goto proceed;

	if (!realpath(lib_path, path)) {
		fprintf(stderr, "failed to get absolute path of '%s' (err %d), using path as is...\n",
			lib_path, -errno);
		secex_strlcpy(path, lib_path, sizeof(path));
	}

proceed:
	sprintf(line, "/proc/%d/maps", pid);
	f = fopen(line, "r");
	if (!f) {
		err = -errno;
		fprintf(stderr, "failed to open '%s' to get base addr of '%s': %d\n",
			line, lib_path, err);
		return err;
	}

	/* We need to handle lines with no path at the end */
	while (fscanf(f, "%zx-%zx %s %zx %*s %*d%[^\n]\n",
		      &seg_start, &seg_end, mode, &seg_off, line) == 5) {
		void *tmp;

		/* to handle no path case (see above) we need to capture line
		 * without skipping any whitespaces. So we need to strip
		 * leading whitespaces manually here
		 */
		i = 0;
		while (isblank(line[i]))
			i++;
		if (strcmp(line + i, path) != 0)
			continue;

		// fprintf(stdout, "usdt: discovered segment for lib '%s': addrs %zx-%zx mode %s offset %zx\n",
		// 	 path, seg_start, seg_end, mode, seg_off);

		/* ignore non-executable sections for shared libs */
		if (mode[2] != 'x')
			continue;

		tmp = secex_reallocarray(*segs, *seg_cnt + 1, sizeof(**segs));
		if (!tmp) {
			err = -ENOMEM;
			goto err_out;
		}

		*segs = tmp;
		seg = *segs + *seg_cnt;
		*seg_cnt += 1;

		seg->start = seg_start;
		seg->end = seg_end;
		seg->offset = seg_off;
		seg->is_exec = true;
	}

	if (*seg_cnt == 0) {
		fprintf(stderr, "failed to find '%s' (resolved to '%s') within PID %d memory mappings\n",
			lib_path, path, pid);
		err = -ESRCH;
		goto err_out;
	}

	qsort(*segs, *seg_cnt, sizeof(**segs), cmp_elf_segs);
	err = 0;
err_out:
	fclose(f);
	return err;
}

struct elf_seg *find_vma_seg(struct elf_seg *segs, size_t seg_cnt, long offset)
{
	struct elf_seg *seg;
	size_t i;

	/* for VMA segments from /proc/<pid>/maps file, provided "address" is
	 * actually a file offset, so should be fall within logical
	 * offset-based range of [offset_start, offset_end)
	 */
	for (i = 0, seg = segs; i < seg_cnt; i++, seg++) {
		if (seg->offset <= offset && offset < seg->offset + (seg->end - seg->start))
			return seg;
	}
	return NULL;
}
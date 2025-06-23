#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <asm/ptrace.h>
#include <errno.h>
#include <libelf.h>
#include <gelf.h>


#include "elf.h"
#include "probe.h"
#include "common.h"

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

/* Architecture-specific logic for parsing argument location specs */

static int calc_pt_regs_off(const char *reg_name)
{
	static struct {
		const char *names[4];
		size_t pt_regs_off;
	} reg_map[] = {
#ifdef __x86_64__
#define reg_off(reg64, reg32) offsetof(struct pt_regs, reg64)
#else
#define reg_off(reg64, reg32) offsetof(struct pt_regs, reg32)
#endif
		{ {"rip", "eip", "", ""}, reg_off(rip, eip) },
		{ {"rax", "eax", "ax", "al"}, reg_off(rax, eax) },
		{ {"rbx", "ebx", "bx", "bl"}, reg_off(rbx, ebx) },
		{ {"rcx", "ecx", "cx", "cl"}, reg_off(rcx, ecx) },
		{ {"rdx", "edx", "dx", "dl"}, reg_off(rdx, edx) },
		{ {"rsi", "esi", "si", "sil"}, reg_off(rsi, esi) },
		{ {"rdi", "edi", "di", "dil"}, reg_off(rdi, edi) },
		{ {"rbp", "ebp", "bp", "bpl"}, reg_off(rbp, ebp) },
		{ {"rsp", "esp", "sp", "spl"}, reg_off(rsp, esp) },
#undef reg_off
#ifdef __x86_64__
		{ {"r8", "r8d", "r8w", "r8b"}, offsetof(struct pt_regs, r8) },
		{ {"r9", "r9d", "r9w", "r9b"}, offsetof(struct pt_regs, r9) },
		{ {"r10", "r10d", "r10w", "r10b"}, offsetof(struct pt_regs, r10) },
		{ {"r11", "r11d", "r11w", "r11b"}, offsetof(struct pt_regs, r11) },
		{ {"r12", "r12d", "r12w", "r12b"}, offsetof(struct pt_regs, r12) },
		{ {"r13", "r13d", "r13w", "r13b"}, offsetof(struct pt_regs, r13) },
		{ {"r14", "r14d", "r14w", "r14b"}, offsetof(struct pt_regs, r14) },
		{ {"r15", "r15d", "r15w", "r15b"}, offsetof(struct pt_regs, r15) },
#endif
	};
	size_t i, j;

	for (i = 0; i < ARRAY_SIZE(reg_map); i++) {
		for (j = 0; j < ARRAY_SIZE(reg_map[i].names); j++) {
			if (strcmp(reg_name, reg_map[i].names[j]) == 0)
				return reg_map[i].pt_regs_off;
		}
	}

	fprintf(stderr, "unrecognized register '%s'\n", reg_name);
	return -ENOENT;
}


/**
 * Parses a string containing a DTrace probe argument specification and fills
 * in a `struct arg_spec` structure with the parsed information.
 *
 * @param arg_str A string containing the argument specification to be parsed.
 * @param arg_num The index of the argument being parsed (0-based).
 * @param arg     A pointer to a `struct arg_spec` structure to be filled
 *                in with the parsed information.
 *
 * @return Returns 0 on success, or a negative error code if an error occurred.
 *
 */

static int parse_probe_arg(const char *arg_str, int arg_num, struct arg_spec *arg)
{
	char reg_name[16];
	int arg_sz, len, reg_off;
	long off;

	if (sscanf(arg_str, " %d @ %ld ( %%%15[^)] ) %n", &arg_sz, &off, reg_name, &len) == 3) {
		/* Memory dereference case, e.g., -4@-20(%rbp) */
		arg->arg_type = ARG_REG_DEREF;
		arg->val_off = off;
		reg_off = calc_pt_regs_off(reg_name);
		if (reg_off < 0)
			return reg_off;
		arg->reg_off = reg_off;
	} else if (sscanf(arg_str, " %d @ %%%15s %n", &arg_sz, reg_name, &len) == 2) {
		/* Register read case, e.g., -4@%eax */
		arg->arg_type = ARG_REG;
		arg->val_off = 0;

		reg_off = calc_pt_regs_off(reg_name);
		if (reg_off < 0)
			return reg_off;
		arg->reg_off = reg_off;
	} else if (sscanf(arg_str, " %d @ $%ld %n", &arg_sz, &off, &len) == 2) {
		/* Constant value case, e.g., 4@$71 */
		arg->arg_type = ARG_CONST;
		arg->val_off = off;
		arg->reg_off = 0;
	} else {
		fprintf(stderr, "unrecognized arg #%d spec '%s'\n", arg_num, arg_str);
		return -EINVAL;
	}

	arg->arg_signed = arg_sz < 0;
	if (arg_sz < 0)
		arg_sz = -arg_sz;

	switch (arg_sz) {
	case 1: case 2: case 4: case 8:
		arg->arg_bitshift = 64 - arg_sz * 8;
		break;
	default:
		fprintf(stderr, "unsupported arg #%d (spec '%s') size: %d\n",
			arg_num, arg_str, arg_sz);
		return -EINVAL;
	}

	return len;
}

/**
 * Given a probe_note, get a string containing the argument specification
 * in `not->args`, walk through the entire string to populate the array of `spec->args[]`
 *
 * @param spec The probe's specification to be filled
 * @param note The probe's note
 *
 * @return Returns 0 on success, or a negative error code if an error occurred.
 *
 */

static int parse_probe_spec(struct probe_spec *spec, const struct probe_note *note)
{
	const char *s;
	int len;

	spec->arg_cnt = 0;

	s = note->args;
	while (s[0]) {
		if (spec->arg_cnt >= PROBE_MAX_ARG_CNT) {
			fprintf(stderr, "too many USDT arguments (> %d) for '%s:%s' with args spec '%s'\n",
				PROBE_MAX_ARG_CNT, note->provider, note->name, note->args);
			return -E2BIG;
		}

		len = parse_probe_arg(s, spec->arg_cnt, &spec->args[spec->arg_cnt]);
		if (len < 0)
			return len;

		s += len;
		spec->arg_cnt++;
	}
	return 0;
}

static int parse_probe_note(GElf_Nhdr *nhdr,
			   const char *data, size_t name_off, size_t desc_off,
			   struct probe_note *note)
{
	const char *provider, *name, *args;
	long addrs[3];
	size_t len;

	/* sanity check note name and type first */
	if (strncmp(data + name_off, NOTE_NAME, nhdr->n_namesz) != 0)
		return -EINVAL;
	if (nhdr->n_type != NOTE_TYPE)
		return -EINVAL;

	/* sanity check note contents ("description" in ELF terminology) */
	len = nhdr->n_descsz;
	data = data + desc_off;

	/* +3 is the very minimum required to store three empty strings */
	if (len < sizeof(addrs) + 3)
		return -EINVAL;

	/* get location, base, and semaphore addrs */
	memcpy(&addrs, data, sizeof(addrs));

	/* parse string fields: provider, name, args */
	provider = data + sizeof(addrs);

	name = (const char *)memchr(provider, '\0', data + len - provider);
	if (!name) /* non-zero-terminated provider */
		return -EINVAL;
	name++;
	if (name >= data + len || *name == '\0') /* missing or empty name */
		return -EINVAL;

	args = memchr(name, '\0', data + len - name);
	if (!args) /* non-zero-terminated name */
		return -EINVAL;
	++args;
	if (args >= data + len) /* missing arguments spec */
		return -EINVAL;

	note->provider = provider;
	note->name = name;
	if (*args == '\0' || *args == ':')
		note->args = "";
	else
		note->args = args;
	note->loc_addr = addrs[0];
	note->base_addr = addrs[1];
	note->sema_addr = addrs[2];

	return 0;
}


int collect_probe_targets(Elf *elf, const char *path, pid_t pid,
				const char *usdt_provider, const char *usdt_name,
				struct probe_target **out_targets, size_t *out_target_cnt)
{
	size_t off, name_off, desc_off, seg_cnt = 0, vma_seg_cnt = 0, target_cnt = 0;
	struct elf_seg *segs = NULL, *vma_segs = NULL;
	struct probe_target *targets = NULL, *target;
	long base_addr = 0;
	Elf_Scn *notes_scn, *base_scn;
	GElf_Shdr base_shdr, notes_shdr;
	GElf_Ehdr ehdr;
	GElf_Nhdr nhdr;
	Elf_Data *data;
	int err;

	*out_targets = NULL;
	*out_target_cnt = 0;



	err = find_elf_sec_by_name(elf, NOTE_SEC, &notes_shdr, &notes_scn);
	if (err) {
		fprintf(stderr, "no USDT notes section (%s) found in '%s'\n", NOTE_SEC, path);
		return err;
	}

	if (notes_shdr.sh_type != SHT_NOTE || !gelf_getehdr(elf, &ehdr)) {
		fprintf(stderr, "invalid USDT notes section (%s) in '%s'\n", NOTE_SEC, path);
		return -EINVAL;
	}

	err = parse_elf_segs(elf, path, &segs, &seg_cnt);
	if (err) {
		fprintf(stderr, "failed to process ELF program segments for '%s': %d\n", path, err);
		goto err_out;
	}

	/* .stapsdt.base ELF section is optional, but is used for prelink
	 * offset compensation (see a big comment further below)
	 */
	if (find_elf_sec_by_name(elf, BASE_SEC, &base_shdr, &base_scn) == 0)
		base_addr = base_shdr.sh_addr;

	data = elf_getdata(notes_scn, 0);
	off = 0;
	while ((off = gelf_getnote(data, off, &nhdr, &name_off, &desc_off)) > 0) {
		long usdt_abs_ip, usdt_rel_ip, usdt_sema_off = 0;
		struct probe_note note;
		struct elf_seg *seg = NULL;
		void *tmp;

		err = parse_probe_note(&nhdr, data->d_buf, name_off, desc_off, &note);
		if (err)
			goto err_out;
        // fprintf(stdout, "usdt: note.provider:%s, note.name:%s\n", note.provider, note.name);
		if (strcmp(note.provider, usdt_provider) != 0 || strcmp(note.name, usdt_name) != 0)
			continue;

		/* We need to compensate "prelink effect". See [0] for details,
		 * relevant parts quoted here:
		 *
		 * Each SDT probe also expands into a non-allocated ELF note. You can
		 * find this by looking at SHT_NOTE sections and decoding the format;
		 * see below for details. Because the note is non-allocated, it means
		 * there is no runtime cost, and also preserved in both stripped files
		 * and .debug files.
		 *
		 * However, this means that prelink won't adjust the note's contents
		 * for address offsets. Instead, this is done via the .stapsdt.base
		 * section. This is a special section that is added to the text. We
		 * will only ever have one of these sections in a final link and it
		 * will only ever be one byte long. Nothing about this section itself
		 * matters, we just use it as a marker to detect prelink address
		 * adjustments.
		 *
		 * Each probe note records the link-time address of the .stapsdt.base
		 * section alongside the probe PC address. The decoder compares the
		 * base address stored in the note with the .stapsdt.base section's
		 * sh_addr. Initially these are the same, but the section header will
		 * be adjusted by prelink. So the decoder applies the difference to
		 * the probe PC address to get the correct prelinked PC address; the
		 * same adjustment is applied to the semaphore address, if any.
		 *
		 *   [0] https://sourceware.org/systemtap/wiki/UserSpaceProbeImplementation
		 */
		usdt_abs_ip = note.loc_addr;
		if (base_addr)
			usdt_abs_ip += base_addr - note.base_addr;

		/* When attaching uprobes (which is what USDTs basically are)
		 * kernel expects file offset to be specified, not a relative
		 * virtual address, so we need to translate virtual address to
		 * file offset, for both ET_EXEC and ET_DYN binaries.
		 */
		seg = find_elf_seg(segs, seg_cnt, usdt_abs_ip);
		if (!seg) {
			err = -ESRCH;
			fprintf(stderr, "failed to find ELF program segment for '%s:%s' in '%s' at IP 0x%lx\n",
				usdt_provider, usdt_name, path, usdt_abs_ip);
			goto err_out;
		}
		if (!seg->is_exec) {
			err = -ESRCH;
			fprintf(stderr, "matched ELF binary '%s' segment [0x%lx, 0x%lx) for '%s:%s' at IP 0x%lx is not executable\n",
				path, seg->start, seg->end, usdt_provider, usdt_name,
				usdt_abs_ip);
			goto err_out;
		}
		/* translate from virtual address to file offset */
		usdt_rel_ip = usdt_abs_ip - seg->start + seg->offset;

		if (ehdr.e_type == ET_DYN) {
			/* If we need to
			 * attach to a shared library, we'll need to know and
			 * record absolute addresses of attach points due to
			 * the need to lookup USDT spec by absolute IP of
			 * triggered uprobe. Doing this resolution is only
			 * possible when we have a specific PID of the process
			 * that's using specified shared library. BPF cookie
			 * removes the absolute address limitation as we don't
			 * need to do this lookup (we just use BPF cookie as
			 * an index of USDT spec), so for newer kernels with
			 * BPF cookie support libbpf supports USDT attachment
			 * to shared libraries with no PID filter.
			 */
			if (pid < 0) {
				fprintf(stderr, "attaching to shared libraries without specific PID is not supported on current kernel\n");
				err = -ENOTSUP;
				goto err_out;
			}

			/* vma_segs are lazily initialized only if necessary */
			if (vma_seg_cnt == 0) {
				err = parse_vma_segs(pid, path, &vma_segs, &vma_seg_cnt);
				if (err) {
					fprintf(stderr, "failed to get memory segments in PID %d for shared library '%s': %d\n",
						pid, path, err);
					goto err_out;
				}
			}

			seg = find_vma_seg(vma_segs, vma_seg_cnt, usdt_rel_ip);
			if (!seg) {
				err = -ESRCH;
				fprintf(stderr, "failed to find shared lib memory segment for '%s:%s' in '%s' at relative IP 0x%lx\n",
					usdt_provider, usdt_name, path, usdt_rel_ip);
				goto err_out;
			}

			usdt_abs_ip = seg->start - seg->offset + usdt_rel_ip;
		}

		fprintf(stdout, "probe for '%s:%s' in %s '%s': addr 0x%lx base 0x%lx (resolved abs_ip 0x%lx rel_ip 0x%lx) args '%s' in segment [0x%lx, 0x%lx) at offset 0x%lx\n",
			 usdt_provider, usdt_name, ehdr.e_type == ET_EXEC ? "exec" : "lib ", path,
			 note.loc_addr, note.base_addr, usdt_abs_ip, usdt_rel_ip, note.args,
			 seg ? seg->start : 0, seg ? seg->end : 0, seg ? seg->offset : 0);

		/* Adjust semaphore address to be a file offset */
		if (note.sema_addr) {

			seg = find_elf_seg(segs, seg_cnt, note.sema_addr);
			if (!seg) {
				err = -ESRCH;
				fprintf(stderr, "failed to find ELF loadable segment with semaphore of '%s:%s' in '%s' at 0x%lx\n",
					usdt_provider, usdt_name, path, note.sema_addr);
				goto err_out;
			}
			if (seg->is_exec) {
				err = -ESRCH;
				fprintf(stdout, "matched ELF binary '%s' segment [0x%lx, 0x%lx] for semaphore of '%s:%s' at 0x%lx is executable\n",
					path, seg->start, seg->end, usdt_provider, usdt_name,
					note.sema_addr);
				goto err_out;
			}

			usdt_sema_off = note.sema_addr - seg->start + seg->offset;

			fprintf(stdout, "sema for '%s:%s' in %s '%s': addr 0x%lx base 0x%lx (resolved 0x%lx) in segment [0x%lx, 0x%lx] at offset 0x%lx\n",
				 usdt_provider, usdt_name, ehdr.e_type == ET_EXEC ? "exec" : "lib ",
				 path, note.sema_addr, note.base_addr, usdt_sema_off,
				 seg->start, seg->end, seg->offset);
		}

		/* Record adjusted addresses and offsets and parse USDT spec */
		tmp = secex_reallocarray(targets, target_cnt + 1, sizeof(*targets));
		if (!tmp) {
			err = -ENOMEM;
			fprintf(stderr, "secex_reallocarray failed\n");
			goto err_out;
		}
		targets = tmp;

		target = &targets[target_cnt];
		memset(target, 0, sizeof(*target));

		target->abs_ip = usdt_abs_ip;
		target->rel_ip = usdt_rel_ip;
		target->sema_off = usdt_sema_off;

		/* notes.args references strings from Elf itself, so they can
		 * be referenced safely until elf_end() call
		 */
		target->spec_str = note.args;

		err = parse_probe_spec(&target->spec, &note);
		if (err)
			goto err_out;

		target_cnt++;
	}

	*out_targets = targets;
	*out_target_cnt = target_cnt;
	err = target_cnt;

err_out:
	free(segs);
	free(vma_segs);
	if (err < 0)
		free(targets);
	return err;
}
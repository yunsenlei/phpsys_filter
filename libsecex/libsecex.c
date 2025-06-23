#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <asm/unistd.h>
#include <linux/perf_event.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <libelf.h>
#include <gelf.h>

#include "probe.h"
#include "libsecex.h"

#define PMU_TYPE_FILE "/sys/bus/event_source/devices/%s/type"

static long
perf_event_open(struct perf_event_attr *attr, pid_t pid, int cpu, int group_fd, unsigned long flags)
{
    int ret;
    ret = syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
    return ret;
}

/** The type file contains a number which is used to specify the perf_event_attr.type.
 *  This function read the file and return the corresponding type's value
 */
static int find_probe_type(const char *event_type){
    int fd;
    int ret;
    char buf[4096];

    /* invalid names */
    ret = snprintf(buf, sizeof(buf), PMU_TYPE_FILE, event_type);
    if (ret < 0 || (unsigned long)ret >= sizeof(buf)){
        return -1;
    }

    /* try to open file and read and type number */
    fd = open(buf, O_RDONLY);
    if (fd < 0){
        return -1;
    }
    ret = read(fd, buf, sizeof(buf));
    close(fd);
    if (ret < 0 || (unsigned long)ret >= sizeof(buf)){
        return -1;
    }
    errno = 0;
    ret = (int)strtol(buf, NULL, 10);
    return errno ? -1 : ret;
}


static inline __u64 ptr_to_u64(const void *ptr)
{
	return (__u64) (unsigned long) ptr;
}


/**
 * Open the the /dev/secex_ioctl device, get a file descriptor 
 * 
 * @return Returns file descriptor on success, or a negative error code if an error occurred.
 *
 */
int secex_open(){
    int ret = 0;
    ret = open("/dev/secex_ioctl", O_RDWR);
    if(ret == -1){
        fprintf(stderr, "[secex_open]: open failed with errno %d\n", errno);
        return -1;
    }
    return ret;
}

/**
 * Send a process ID to the device, mark the corresponding process to use
 * our fine-grained system call fiter 
 * 
 * @param fd the file descriptor returned by `secex_open`
 * @param pid the target process ID 
 * 
 * @return Returns 0 on success, or a negative error code if an error occurred.
 *
 */
int secex_init(int fd, pid_t pid){
    struct secex_ctx ctx = { .pid = pid };
    if(ioctl(fd, SECEX_INIT, &ctx) == -1){
        fprintf(stderr, "ioctl failed with errno %d\n", errno);
        return -1;
    }
    return 0;
}

/**
 * Given a process ID and its executable path, find the probe by its provider and name.
 * Store the return the probe specification in a out prameter
 * 
 * @param pid the target process ID 
 * @param path the path of the process's executable
 * @param probe_provider probe's provider name
 * @param probe_name probe's name
 * @param out_targets the probe_target sturct used to store found probe information
 * @param out_target_cnt the number of probe found
 * 
 * @return Returns 0 on success, or -1 if an error occurred.
 *
 */
int secex_find_probe(pid_t pid, const char* path, const char *probe_provider, const char *probe_name, struct probe_target **out_targets, size_t *out_target_cnt){
    int ret, fd;
    Elf *elf;
    char binary_path[4096] = {0};
    
    ret = snprintf(binary_path, sizeof(binary_path), "/proc/%d/root%s", pid, path);
    if (ret < 0 || (unsigned long)ret >= sizeof(binary_path)){
        fprintf(stderr, "[secex_find_probe]: failed to copy path\n");
        return -1;
    }

    /* init the elf library and open the file */
	fd = open(binary_path, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "[secex_find_probe]: failed to open %s with error %s\n", binary_path, strerror(errno));
		return -1;
	}

	if (elf_version(EV_CURRENT) == EV_NONE) {
		fprintf(stderr, "[secex_find_probe]: failed to init libelf \n");
        close(fd);
		return -1;
	}

	elf = elf_begin(fd, ELF_C_READ_MMAP, NULL);
	if (!elf) {
		fprintf(stderr, "[secex_find_probe]: could not read elf from %s: %s\n", binary_path, elf_errmsg(-1));
		close(fd);
		return -1;
	}

    ret = collect_probe_targets(elf, binary_path, pid, probe_provider, probe_name, out_targets, out_target_cnt);
    if(ret < 0){
        fprintf(stderr, "[secex_find_probe]: failed to collect probe spec from the binary, return code %d\n", ret);
        close(fd);
        return -1;
    }

    close(fd);
    return 0;
}

/**
 * Perform perf_event_open on a given proces, given the probe's informaion and the process path
 * 
 * @param target the probe's information, obtained using `collect_probe_targets`
 * @param pid the target process ID 
 * @param binary_path the path of the process's executable
 * 
 * @return Returns perf_event's file descriptor on success, or a negative error code if an error occurred.
 *
 */
int secex_enable_probe(struct probe_target *target, pid_t pid, const char* binary_path){
    
    /* prepare the event attribute used in the perf_event_open system call */
    int ret;
    char path[4096] = {0};
    
    ret = snprintf(path, sizeof(path), "/proc/%d/root%s", pid, binary_path);
    if (ret < 0 || (unsigned long)ret >= sizeof(path)){
        fprintf(stderr, "[secex_find_probe]: failed to copy path\n");
        return -1;
    }

    struct perf_event_attr attr;    
    memset(&attr, 0, sizeof(attr));
    attr.type = find_probe_type("secex_probe");
    attr.size = sizeof(attr);
	attr.config  = target->sema_off;
    attr.config1 = ptr_to_u64(path);
	attr.config2 = target->rel_ip;
	attr.sample_period = 1;
	attr.sample_type = 0;

    int pfd = perf_event_open(&attr, pid, -1, -1, 0); // cpu, group_fd = -1, flag = 0

	if(pfd < 0){
		fprintf(stderr, "[secex_enable_probe]: perf_event_open failed with error %s\n", strerror(errno));
	}
    return pfd;
}

/**
 * Pass the probe's specification to the kernel so the kernel knows how to read the user-level event data
 * 
 * @param fd the file descriptor to our secex device
 * @param ctx the context data needed to perform the operation, including a probe's specification and the file descriptor to opened perf_event 
 * 
 * @return Returns 0 on success, or a negative error code if an error occurred.
 *
 */
int secex_set_probe_spec(int fd, struct secex_probe_ctx *ctx){
    int ret = ioctl(fd, SECEX_SET_PROBE_SPEC, ctx);
    if(ret == -1){
		fprintf(stderr, "[secex_set_probe_spec]: failed with error %s\n", strerror(errno));
	}
    return ret;
}

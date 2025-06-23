#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/select.h>
#include "libsecex.h"
int main(int argc, char const *argv[])
{
    char *endptr;
    int secex_fd, perf_fd, ret;
    size_t target_cnt;
    struct probe_target *target1, *target2, *target3;
    struct secex_probe_ctx ctx;
    if(argc != 2){
        fprintf(stderr, "usage: ./test [pid]\n");
        return -1;
    }
    pid_t pid = (pid_t)strtol(argv[1], &endptr, 10);
    
    if (*endptr != '\0') {
        fprintf(stderr, "invalid process ID %s\n", argv[1]);
        return -1;
    }

    secex_fd = secex_open();
    if(secex_fd < 0){
        fprintf(stderr, "cannot open the secex device\n");
        return -1;
    }

    ret = secex_init(secex_fd, pid);
    if(ret < 0){
        fprintf(stderr, "failed to enable secex filter on process %d\n", pid);
        return -1;
    }

    /* request__startup */
    ret = secex_find_probe(pid, "/opt/php-7.4/lib/php/extensions/debug-non-zts-20190902/php_secex.so", "secex", "request__startup", &target1, &target_cnt);
    if(ret < 0){
        fprintf(stderr, "cannot find the requested probe in process\n");
        return -1;
    }

    if(target_cnt != 1){
        fprintf(stderr, "this test program only enable a single probe, multiple probes should be enabled with multiple perf_event_open\n");
        return -1;
    }

    perf_fd = secex_enable_probe(&target1[0], pid, "/opt/php-7.4/lib/php/extensions/debug-non-zts-20190902/php_secex.so");
    if(perf_fd < 0){
        fprintf(stderr, "failed to enable the probe\n");
        return -1;
    }
    memset(&ctx, 0, sizeof(ctx));
    ctx.fd = perf_fd;
    ctx.specs.arg_cnt = target1[0].spec.arg_cnt;
    ctx.specs.pid = pid;
    ctx.specs.event_type = PROBE_REQ_START;
    memcpy(ctx.specs.args, target1[0].spec.args, sizeof(struct arg_spec) * ctx.specs.arg_cnt);
    printf("set request__startup spec: arg_cnt = %hd\n", target1[0].spec.arg_cnt);
    ret = secex_set_probe_spec(secex_fd, &ctx);
    if(ret < 0){
        fprintf(stderr, "failed to set the specification for the probe\n");
        return -1;
    }

    /* request__shutdown */
    ret = secex_find_probe(pid, "/opt/php-7.4/lib/php/extensions/debug-non-zts-20190902/php_secex.so", "secex", "request__shutdown", &target2, &target_cnt);
    if(ret < 0){
        fprintf(stderr, "cannot find request__shutdown probe in process\n");
        return -1;
    }

    if(target_cnt != 1){
        fprintf(stderr, "this test program only enable a single probe, multiple probes should be enabled with multiple perf_event_open\n");
        return -1;
    }

    perf_fd = secex_enable_probe(&target2[0], pid, "/opt/php-7.4/lib/php/extensions/debug-non-zts-20190902/php_secex.so");
    if(perf_fd < 0){
        fprintf(stderr, "failed to enable the request__shutdown probe\n");
        return -1;
    }

    memset(&ctx, 0, sizeof(ctx));
    ctx.fd = perf_fd;
    ctx.specs.arg_cnt = target2[0].spec.arg_cnt;
    ctx.specs.pid = pid;
    ctx.specs.event_type = PROBE_REQ_SHUTDOWN;
    memcpy(ctx.specs.args, target2[0].spec.args, sizeof(struct arg_spec) * ctx.specs.arg_cnt);
    printf("set request__shutdown spec: arg_cnt = %hd\n", target2[0].spec.arg_cnt);
    ret = secex_set_probe_spec(secex_fd, &ctx);
    if(ret < 0){
        fprintf(stderr, "failed to set the specification for the probe\n");
        return -1;
    }

    /* function_execute */
    ret = secex_find_probe(pid, "/opt/php-7.4/lib/php/extensions/debug-non-zts-20190902/php_secex.so", "secex", "function_execute", &target3, &target_cnt);
    if(ret < 0){
        fprintf(stderr, "cannot find function_execute probe in process\n");
        return -1;
    }

    if(target_cnt != 1){
        fprintf(stderr, "this test program only enable a single probe, multiple probes should be enabled with multiple perf_event_open\n");
        return -1;
    }

    perf_fd = secex_enable_probe(&target3[0], pid, "/opt/php-7.4/lib/php/extensions/debug-non-zts-20190902/php_secex.so");
    if(perf_fd < 0){
        fprintf(stderr, "failed to enable the function_execute probe\n");
        return -1;
    }
    memset(&ctx, 0, sizeof(ctx));
    ctx.fd = perf_fd;
    ctx.specs.arg_cnt = target3[0].spec.arg_cnt;
    ctx.specs.pid = pid;
    ctx.specs.event_type = PROBE_FUNC;
    memcpy(ctx.specs.args, target3[0].spec.args, sizeof(struct arg_spec) * ctx.specs.arg_cnt);
    printf("set function_execute spec: arg_cnt = %hd\n", target3[0].spec.arg_cnt);
    ret = secex_set_probe_spec(secex_fd, &ctx);
    if(ret < 0){
        fprintf(stderr, "failed to set the specification for the probe\n");
        return -1;
    }

    /* This is just used to prevent the program from ending and closing the per_fd*/
	fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(0, &rfds);

    ret = select(1, &rfds, NULL, NULL, NULL);

    if (ret == -1) {
        perror("select");
        exit(-1);
    } else if (ret) {
        printf("End the probram\n");
    }

    close(perf_fd);
    close(secex_fd);
    return 0;
}

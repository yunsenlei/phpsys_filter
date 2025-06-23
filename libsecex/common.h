#ifndef __LIB_SECEX_COMMON_H
#define __LIB_SECEX_COMMON_H

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <asm/ptrace.h>

#ifndef likely
#define likely(x) __builtin_expect(!!(x), 1)
#endif

#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

static inline void *secex_reallocarray(void *ptr, size_t nmemb, size_t size)
{
	size_t total;

#if __has_builtin(__builtin_mul_overflow)
	if (unlikely(__builtin_mul_overflow(nmemb, size, &total)))
		return NULL;
#else
	if (size == 0 || nmemb > ULONG_MAX / size)
		return NULL;
	total = nmemb * size;
#endif
	return realloc(ptr, total);
}
#endif

#ifndef TEAVPN2__GLOBAL__HELPERS__MEMORY_H
#define TEAVPN2__GLOBAL__HELPERS__MEMORY_H

#include <stddef.h>
#include <string.h>

#if defined(__x86_64__) && defined(__linux__)
#  define NEED_MEMCPY_TEST 1
#  define ar_memcpy ar_memcpy_x86_64

inline static void *
ar_memcpy_x86_64(void *restrict dest, const void *restrict src, size_t n)
{
  __asm__ volatile(
    "cld\n\t"
    "rep movsb"
    : "+D"(dest), "+S"(src), "+c"(n)
    :
    : "memory", "cc"
  );
  return dest;
}

#else /* #if defined(__x86_64__) && defined(__linux__) */

/* We believe in libc, so no need to test. */
#  define NEED_MEMCPY_TEST 0
#  define ar_memcpy memcpy

#endif /* #if defined(__x86_64__) && defined(__linux__) */


void
ar_init(void *_arena_ptr, size_t _arena_size);

void *
ar_alloc(size_t len);

char *
ar_strdup(const char *str);

char *
ar_strndup(const char *str, size_t maxlen);


#endif /* #ifndef TEAVPN2__GLOBAL__HELPERS__MEMORY_H */

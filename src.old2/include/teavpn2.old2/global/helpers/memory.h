
#ifndef TEAVPN2__GLOBAL__HELPERS__MEMORY_H
#define TEAVPN2__GLOBAL__HELPERS__MEMORY_H

#if defined(__x86_64__) && defined(__linux__)

inline static void *
t_ar_memcpy_x86_64(void *__restrict__ dest,
                   const void *__restrict__ src, size_t n)
{
  __asm__ volatile(
    "rep movsb"
    : "+D"(dest), "+S"(src), "+c"(n)
    :
    : "memory"
  );
  return dest;
}

#  define NEED_MEMCPY_TEST 1
#  define t_ar_memcpy t_ar_memcpy_x86_64
#else /* #if defined(__x86_64__) && defined(__linux__) */
/* We believe in libc, so no need to test. */
#  include <string.h>
#  define NEED_MEMCPY_TEST 0
#  define t_ar_memcpy memcpy
#endif /* #if defined(__x86_64__) && defined(__linux__) */


void
t_ar_init(void *ptr, size_t len);

void *
t_ar_alloc(size_t len);

char *
t_ar_strdup(const char *str);

char *
t_ar_strndup(const char *str, size_t tlen);


#endif

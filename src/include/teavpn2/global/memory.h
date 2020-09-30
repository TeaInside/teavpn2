
#ifndef TEAVPN2__GLOBAL__MEMORY_H
#define TEAVPN2__GLOBAL__MEMORY_H

#include <stdio.h>
#if defined(__x86_64__)

inline static void *__internal_t_ar_memcpy_x86_64(
  register void *dest,
  register const void *src,
  register size_t n
) {
  // if (n == 1) {
  //   *((char *)dest) = *((char *)src);
  // } else {
    __asm__ volatile(
      "mov %0, %%rdi;"
      "mov %1, %%rsi;"
      "mov %2, %%rcx;"
      "rep movsb;"
      :
      : "r"(dest), "r"(src), "r"(n)
      : "rdi", "rsi", "rcx"
    );
  //}
  return dest;
}

#define NEED_MEMCPY_TEST 1
#define t_ar_memcpy __internal_t_ar_memcpy_x86_64
 
#else

/* Use default memcpy from <string.h> */
#include <string.h>
#define NEED_MEMCPY_TEST 0   /* We believe in libc, so no need to test. */
#define t_ar_memcpy memcpy

#endif

void t_ar_init(register void *ptr, register size_t len);
void *t_ar_alloc(register size_t len);
char *t_ar_strdup(register const char *str);
char *t_ar_strndup(register const char *str, register size_t tlen);

#endif

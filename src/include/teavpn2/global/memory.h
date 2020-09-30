
#ifndef TEAVPN2__GLOBAL__MEMORY_H
#define TEAVPN2__GLOBAL__MEMORY_H

#if defined(__x86_64__)
#define t_ar_memcpy(DST, SRC, N)    \
  __asm__(                          \
    "mov %0, %%rdi;"                \
    "mov %1, %%rsi;"                \
    "mov %2, %%rcx;"                \
    "rep movsb"                     \
    :                               \
    : "r"(DST), "r"(SRC), "r"(N)    \
    : "rdi", "rsi", "rcx"           \
  )
#else
#define t_ar_memcpy memcpy
#endif

#endif

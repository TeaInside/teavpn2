

#ifndef TEAVPN__GLOBAL__ARENA_H
#define TEAVPN__GLOBAL__ARENA_H

char *arena_strdup(const char *str);
void *arena_alloc(register size_t len);
void init_arena(char *arena, size_t arena_size);

#endif

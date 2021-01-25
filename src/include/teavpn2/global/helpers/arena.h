

#ifndef __TEAVPN2__GLOBAL__HELPERS__ARENA_H
#define __TEAVPN2__GLOBAL__HELPERS__ARENA_H

void arena_init(char *arena, size_t arena_size);
size_t arena_unused_size();
void *arena_alloc(size_t len);
void *arena_strdup(const char *str);

#endif /* #ifndef __TEAVPN2__GLOBAL__HELPERS__ARENA_H */

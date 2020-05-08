
#include <string.h>
#include <teavpn2/global/arena.h>

char *arena_addr;
size_t arena_pos;
size_t arena_size;

void init_arena(char *arena, size_t arena_size)
{
  arena_addr = arena;
  arena_size = arena_size;
  arena_pos = 0;
}

void *arena_alloc(register size_t len)
{
  register char *ret = &(arena_addr[arena_pos]);
  arena_pos += len;
  return ret;
}

char *arena_strdup(const char *str)
{
  size_t len = strlen(str) + 1;
  char *ret = arena_alloc(len);
  memcpy(ret, str, len);
  return ret;
}

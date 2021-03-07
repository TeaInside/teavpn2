
#include <string.h>
#include <teavpn2/global/arena.h>

/**
 * Warning:
 * - You must be very very careful in using arena.
 * - It does not have free() like malloc() does.
 * - Responsibility to manage reuse memory is yours.
 * - No deallocation.
 * - No detail valgrind error detection.
 *
 * YOU HAVE BEEN WARNED!
 */

char *arena_addr;
size_t arena_pos;
size_t arena_size;

void init_arena(char *arena, size_t arena_size)
{
  arena_addr = arena;
  arena_size = arena_size;
  arena_pos = 0;
}

size_t arena_unused_size()
{
  return arena_size - arena_pos;
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

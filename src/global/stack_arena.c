
#include <assert.h>
#include <string.h>
#include <teavpn/global/common.h>

void    *__stack_arena_ptr   = NULL;
size_t  __stack_arena_length = 0;
size_t  __stack_arena_used   = 0;

/**
 * @param void    *ptr
 * @param size_t  length
 * @return void
 */
void init_stack_arena(void *ptr, size_t length)
{
  __stack_arena_ptr    = ptr;
  __stack_arena_length = length;
  __stack_arena_used   = 0;
}

/**
 * @param register size_t length
 * @return void *
 */
void *stack_arena_alloc(register size_t length)
{
  register void *ret;

  ret = &(((char *)__stack_arena_ptr)[__stack_arena_used]);

  __stack_arena_used += length;

  return ret;
}

/**
 * @param const char *str
 * @return char *
 */
char *stack_strdup(const char *str)
{
  register char *ret;

  ret = (char *)stack_arena_alloc(strlen(str) + 1);
  strcpy(ret, str);

  return ret;
}

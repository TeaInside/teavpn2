
#include <string.h>

#include <teavpn2/global/common.h>

static void   *__t_arena     = NULL;
static size_t  __t_arena_len = 0;
static size_t  __t_arena_pos = 0;


void t_ar_init(register void *ptr, register size_t len)
{
  __t_arena     = ptr;
  __t_arena_len = len;
}


void *t_ar_alloc(register size_t len)
{
  register char *ret  = &(((char *)__t_arena)[__t_arena_pos]);
  __t_arena_pos      += len;

  return (void *)ret;
}


char *t_ar_strdup(register const char *str)
{
  register size_t len = strlen(str);
  register char *ret  = &(((char *)__t_arena)[__t_arena_pos]);
  __t_arena_pos      += len + 1;

  t_ar_memcpy(ret, str, len);
  ret[len] = '\0';

  return ret;
}


char *t_ar_strndup(register const char *str, register size_t tlen)
{
  register size_t len = strlen(str);
  register char *ret  = &(((char *)__t_arena)[__t_arena_pos]);

  tlen = len < tlen ? len : tlen;

  __t_arena_pos += tlen + 1;
  t_ar_memcpy(ret, str, tlen);
  ret[tlen] = '\0';

  return ret;
}

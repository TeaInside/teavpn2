
#include <stdio.h>
#include <assert.h>
#include <string.h>

#include <criterion/criterion.h>
#include <teavpn2/server/common.h>

Test(memory, contiguous_block_allocation_test)
{
  char arena[4096];
  t_ar_init(arena, sizeof(arena));

  char *a = t_ar_alloc(1024);
  char *b = t_ar_alloc(1024);
  char *c = t_ar_alloc(1024);
  char *d = t_ar_alloc(1024);

  memset(a, 'A', 2048);
  cr_assert(!memcmp(a, b, 1024));

  memset(b, 'B', 2048);
  cr_assert(!memcmp(b, c, 1024));

  memset(c, 'D', 2048);
  cr_assert(!memcmp(c, d, 1024));

  cr_assert(a + 1024 == b);
  cr_assert(b + 1024 == c);
  cr_assert(c + 1024 == d);
}


Test(memory, strdup_test)
{
  char arena[4096];

  /* Initialize arena with 'b'. */
  memset(arena, 'z', sizeof(arena));

  /* Initialize the allocator. */
  t_ar_init(arena, sizeof(arena));


  /* Simple strdup test. */
  {
    char str[] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    char *ptr  = t_ar_strdup(str);

    cr_assert(!memcmp(ptr, str, sizeof(str)));
  }


  /* strndup test. */
  {
    char str[] = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    size_t shorter_len = (sizeof(str) - 1) - 5;

    char *ptr = t_ar_strndup(str, shorter_len);

    /* Copied string from strndup must be null terminated. */
    cr_assert(ptr[shorter_len] == '\0');
  }
}


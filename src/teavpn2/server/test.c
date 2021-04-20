#include "libasm.h"

char *strdup(const char *s);

int main(void)
{

    printf("  _____________\n");
    printf("//             \\\\\n");
    printf("||  ft_strdup  ||\n");
    printf("||_____________||\n");
    char *str;
    char *dup;

    str = "test";
    printf("segfault1\n");
    dup = ft_strdup(str);
    printf("segfault2\n");
    printf("str: %s\n", dup);
    free(dup);
    return 0;
}

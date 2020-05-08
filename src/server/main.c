
#include <stdio.h>
#include <teavpn2/server/common.h>

int main(int argc, char *argv[], char *envp[])
{

  if (argc != 2) {
    printf("Invalid arguments!\n");
    printf("Usage: %s <config_file>\n", argv[0]);
    return 1;
  }

  teavpn_server_config config;
  teavpn_server_config_parser(argv[1], &config);

  return 0;
}

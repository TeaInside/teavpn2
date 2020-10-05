
#include <stdio.h>
#include <string.h>
#include <teavpn2/server/common.h>

#ifndef ARENA_SIZE
#define ARENA_SIZE 4096
#endif


int main(int argc, char *argv[], char *envp[])
{
  char arena[ARENA_SIZE];
  server_cfg config;

  t_ar_init(arena, sizeof(arena));

  if (!tvpn_server_argv_parse(argc, argv, envp, &config)) {
    return 1;
  }

  if (config.config_file) {
    if (!tvpn_server_load_config_file(config.config_file, &config)) {
      return 1;
    }
  }

  server_pkt pkt;
  char x[] = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
  memset(&pkt, 0, sizeof(pkt));
  memcpy(&pkt, x, SRV_IDENT_PKT_SIZE);

  printf("Type: %x\n", pkt.type);
  printf("Size: %x\n", pkt.size);
  printf("Data: %s\n", pkt.data);

  return 0;

  return tvpn_server_run(&config);
}

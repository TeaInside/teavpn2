
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <teavpn2/server/auth.h>
#include <teavpn2/server/common.h>

bool teavpn_server_auth_handle(
  char *username,
  char *password,
  teavpn_server_config *config,
  teavpn_srv_iface_info *iface_info
)
{
  int file_fd;
  ssize_t frlen;
  bool ret = true;
  uint8_t password_len;
  char password_file[512];

  sprintf(password_file, "%s/users/%s/password", config->data_dir, username);
  file_fd = open(password_file, O_RDONLY);

  if (file_fd < 0) {
    debug_log(2, "Invalid username or password!");
    return false; /* No need to close fd, since it fails. */
  }

  password_len = (uint8_t)strlen(password);
  frlen = read(file_fd, password, password_len);
  if (frlen < 0) {
    ret = false;
    debug_log(2, "Cannot read password from file");
    goto close_file_fd;
  }
  password[password_len] = '\0';

  ret = (
    (password_len == ((uint8_t)frlen)) && (!strcmp(password, password))
  );

close_file_fd:
  close(file_fd);
  return ret;
}

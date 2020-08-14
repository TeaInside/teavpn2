
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
  char password_file[512], correct_password[512];

  sprintf(password_file, "%s/users/%s/password", config->data_dir, username);
  file_fd = open(password_file, O_RDONLY);

  if (file_fd < 0) {
    debug_log(2, "Invalid username or password!");
    return false; /* No need to close fd, since it fails. */
  }

  password_len = (uint8_t)strlen(password);
  frlen = read(file_fd, correct_password, password_len);
  if (frlen < 0) {
    ret = false;
    debug_log(2, "Cannot read password from file");
    goto close_file_fd;
  }
  correct_password[password_len] = '\0';

  ret = (
    (password_len == ((uint8_t)frlen)) && (!strcmp(password, correct_password))
  );

  if (ret) {
    char *filename = password_file,
      *inet4 = correct_password;

    close(file_fd); /* Close password file fd. */
    sprintf(password_file, "%s/users/%s/inet4", config->data_dir, username);
    file_fd = open(filename, O_RDONLY);
    if (file_fd < 0) {
      debug_log(2, "Unable to open %s", filename);
      return false; /* No need to close fd, since it fails. */
    }

    frlen = read(file_fd, inet4, 255);
    if (frlen < 0) {
      ret = false;
      debug_log(2, "Cannot read inet4 from file: %s", filename);
      goto close_file_fd;
    }
    inet4[frlen] = '\0';

    for (register int i = 0; i < frlen; ++i) {
      if (inet4[i] == ' ') {
        inet4[i] = '\0';
        strcpy(iface_info->inet4, inet4);
        strcpy(iface_info->inet4_bc, &(inet4[i + 1]));
        ret = true;
        goto close_file_fd;
        break;
      }
    }

    ret = false;
  }

close_file_fd:
  close(file_fd);
  return ret;
}

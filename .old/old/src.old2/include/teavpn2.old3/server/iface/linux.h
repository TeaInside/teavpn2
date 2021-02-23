
#ifndef TEAVPN2__SERVER__IFACE__LINUX_H
#define TEAVPN2__SERVER__IFACE__LINUX_H

int
tun_alloc(char *dev, int flags);

int
tun_set_queue(int fd, bool enable);

#endif /* #ifndef TEAVPN2__SERVER__IFACE__LINUX_H */

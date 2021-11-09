/* SPDX-License-Identifier: MIT */
#define _POSIX_C_SOURCE 200112L

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include "liburing/compat.h"
#include "liburing/io_uring.h"
#include "liburing.h"

#include "syscall.h"

int io_uring_register_buffers_update_tag(struct io_uring *ring, unsigned off,
					 const struct iovec *iovecs,
					 const __u64 *tags,
					 unsigned nr)
{
	struct io_uring_rsrc_update2 up = {
		.offset	= off,
		.data = (unsigned long)iovecs,
		.tags = (unsigned long)tags,
		.nr = nr,
	};
	int ret;

	ret = __sys_io_uring_register(ring->ring_fd,
				      IORING_REGISTER_BUFFERS_UPDATE,
				      &up, sizeof(up));
	return ret < 0 ? -errno : ret;
}

int io_uring_register_buffers_tags(struct io_uring *ring,
				   const struct iovec *iovecs,
				   const __u64 *tags,
				   unsigned nr)
{
	struct io_uring_rsrc_register reg = {
		.nr = nr,
		.data = (unsigned long)iovecs,
		.tags = (unsigned long)tags,
	};
	int ret;

	ret = __sys_io_uring_register(ring->ring_fd, IORING_REGISTER_BUFFERS2,
				      &reg, sizeof(reg));
	return ret < 0 ? -errno : ret;
}

int io_uring_register_buffers(struct io_uring *ring, const struct iovec *iovecs,
			      unsigned nr_iovecs)
{
	int ret;

	ret = __sys_io_uring_register(ring->ring_fd, IORING_REGISTER_BUFFERS,
					iovecs, nr_iovecs);
	if (ret < 0)
		return -errno;

	return 0;
}

int io_uring_unregister_buffers(struct io_uring *ring)
{
	int ret;

	ret = __sys_io_uring_register(ring->ring_fd, IORING_UNREGISTER_BUFFERS,
					NULL, 0);
	if (ret < 0)
		return -errno;

	return 0;
}

int io_uring_register_files_update_tag(struct io_uring *ring, unsigned off,
					const int *files, const __u64 *tags,
					unsigned nr_files)
{
	struct io_uring_rsrc_update2 up = {
		.offset	= off,
		.data = (unsigned long)files,
		.tags = (unsigned long)tags,
		.nr = nr_files,
	};
	int ret;

	ret = __sys_io_uring_register(ring->ring_fd,
					IORING_REGISTER_FILES_UPDATE2,
					&up, sizeof(up));
	return ret < 0 ? -errno : ret;
}

/*
 * Register an update for an existing file set. The updates will start at
 * 'off' in the original array, and 'nr_files' is the number of files we'll
 * update.
 *
 * Returns number of files updated on success, -ERROR on failure.
 */
int io_uring_register_files_update(struct io_uring *ring, unsigned off,
				   int *files, unsigned nr_files)
{
	struct io_uring_files_update up = {
		.offset	= off,
		.fds	= (unsigned long) files,
	};
	int ret;

	ret = __sys_io_uring_register(ring->ring_fd,
					IORING_REGISTER_FILES_UPDATE, &up,
					nr_files);
	if (ret < 0)
		return -errno;

	return ret;
}

static int increase_rlimit_nofile(unsigned nr)
{
	struct rlimit rlim;

	if (getrlimit(RLIMIT_NOFILE, &rlim) < 0)
		return -errno;
	if (rlim.rlim_cur < nr) {
		rlim.rlim_cur += nr;
		setrlimit(RLIMIT_NOFILE, &rlim);
	}

	return 0;
}

int io_uring_register_files_tags(struct io_uring *ring,
				 const int *files, const __u64 *tags,
				 unsigned nr)
{
	struct io_uring_rsrc_register reg = {
		.nr = nr,
		.data = (unsigned long)files,
		.tags = (unsigned long)tags,
	};
	int ret, did_increase = 0;

	do {
		ret = __sys_io_uring_register(ring->ring_fd,
					      IORING_REGISTER_FILES2, &reg,
					      sizeof(reg));
		if (ret >= 0)
			break;
		if (errno == EMFILE && !did_increase) {
			did_increase = 1;
			increase_rlimit_nofile(nr);
			continue;
		}
		break;
	} while (1);

	return ret < 0 ? -errno : ret;
}

int io_uring_register_files(struct io_uring *ring, const int *files,
			      unsigned nr_files)
{
	int ret, did_increase = 0;

	do {
		ret = __sys_io_uring_register(ring->ring_fd,
					      IORING_REGISTER_FILES, files,
					      nr_files);
		if (ret >= 0)
			break;
		if (errno == EMFILE && !did_increase) {
			did_increase = 1;
			increase_rlimit_nofile(nr_files);
			continue;
		}
		break;
	} while (1);

	return ret < 0 ? -errno : ret;
}

int io_uring_unregister_files(struct io_uring *ring)
{
	int ret;

	ret = __sys_io_uring_register(ring->ring_fd, IORING_UNREGISTER_FILES,
					NULL, 0);
	if (ret < 0)
		return -errno;

	return 0;
}

int io_uring_register_eventfd(struct io_uring *ring, int event_fd)
{
	int ret;

	ret = __sys_io_uring_register(ring->ring_fd, IORING_REGISTER_EVENTFD,
					&event_fd, 1);
	if (ret < 0)
		return -errno;

	return 0;
}

int io_uring_unregister_eventfd(struct io_uring *ring)
{
	int ret;

	ret = __sys_io_uring_register(ring->ring_fd, IORING_UNREGISTER_EVENTFD,
					NULL, 0);
	if (ret < 0)
		return -errno;

	return 0;
}

int io_uring_register_eventfd_async(struct io_uring *ring, int event_fd)
{
	int ret;

	ret = __sys_io_uring_register(ring->ring_fd, IORING_REGISTER_EVENTFD_ASYNC,
			&event_fd, 1);
	if (ret < 0)
		return -errno;

	return 0;
}

int io_uring_register_probe(struct io_uring *ring, struct io_uring_probe *p,
			    unsigned int nr_ops)
{
	int ret;

	ret = __sys_io_uring_register(ring->ring_fd, IORING_REGISTER_PROBE,
					p, nr_ops);
	if (ret < 0)
		return -errno;

	return 0;
}

int io_uring_register_personality(struct io_uring *ring)
{
	int ret;

	ret = __sys_io_uring_register(ring->ring_fd, IORING_REGISTER_PERSONALITY,
					NULL, 0);
	if (ret < 0)
		return -errno;

	return ret;
}

int io_uring_unregister_personality(struct io_uring *ring, int id)
{
	int ret;

	ret = __sys_io_uring_register(ring->ring_fd, IORING_UNREGISTER_PERSONALITY,
					NULL, id);
	if (ret < 0)
		return -errno;

	return ret;
}

int io_uring_register_restrictions(struct io_uring *ring,
				   struct io_uring_restriction *res,
				   unsigned int nr_res)
{
	int ret;

	ret = __sys_io_uring_register(ring->ring_fd, IORING_REGISTER_RESTRICTIONS,
				      res, nr_res);
	if (ret < 0)
		return -errno;

	return 0;
}

int io_uring_enable_rings(struct io_uring *ring)
{
	int ret;

	ret = __sys_io_uring_register(ring->ring_fd,
				      IORING_REGISTER_ENABLE_RINGS, NULL, 0);
	if (ret < 0)
		return -errno;

	return ret;
}

int io_uring_register_iowq_aff(struct io_uring *ring, size_t cpusz,
			       const cpu_set_t *mask)
{
	int ret;

	ret = __sys_io_uring_register(ring->ring_fd,
					IORING_REGISTER_IOWQ_AFF, mask, cpusz);
	if (ret < 0)
		return -errno;

	return ret;
}

int io_uring_unregister_iowq_aff(struct io_uring *ring)
{
	int ret;

	ret = __sys_io_uring_register(ring->ring_fd,
					IORING_REGISTER_IOWQ_AFF, NULL, 0);
	if (ret < 0)
		return -errno;

	return ret;
}

int io_uring_register_iowq_max_workers(struct io_uring *ring, unsigned int *val)
{
	int ret;

	ret = __sys_io_uring_register(ring->ring_fd,
					IORING_REGISTER_IOWQ_MAX_WORKERS,
					val, 2);
	if (ret < 0)
		return -errno;

	return ret;

}

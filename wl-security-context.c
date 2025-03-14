#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <poll.h>
#include <sched.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <unistd.h>
#include <wayland-client.h>

#include "security-context-v1-protocol.h"

static int pidfd_open(pid_t pid, unsigned int flags) {
	return (int)syscall(SYS_pidfd_open, pid, flags);
}

static int write_to_fd(int fd, const char *content, ssize_t len) {
	ssize_t res;

	while (len > 0) {
		res = write(fd, content, len);
		if (res < 0 && errno == EINTR) {
			continue;
		}
		if (res <= 0) {
			if (res == 0) {
				errno = ENOSPC;
			}
			return -1;
		}
		len -= res;
		content += res;
	}

	return 0;
}

static char *get_wl_socket(void) {
	const char *name = NULL, *runtime_dir = NULL;
	char *socket_path = NULL;
	bool path_is_absolute = false;
	int ret = 0;

	name = getenv("WAYLAND_DISPLAY");
	if (!name) {
		name = "wayland-0";
	}

	path_is_absolute = name[0] == '/';

	runtime_dir = getenv("XDG_RUNTIME_DIR");
	if ((!runtime_dir || runtime_dir[0] != '/') && !path_is_absolute) {
		return NULL;
	}

	if (!path_is_absolute) {
		ret = asprintf(&socket_path, "%s/%s", runtime_dir, name);
	} else {
		ret = asprintf(&socket_path, "%s", runtime_dir);
	}

	if (ret == -1) {
		return NULL;
	}
	return socket_path;
}

static char *create_wl_socket(char *template) {
	int fd = mkstemp(template);
	if (fd == -1) {
		return NULL;
	}
	close(fd);
	return template;
}

static void registry_handle_global(void *data, struct wl_registry *registry, uint32_t name, const char *interface, uint32_t version) {
	struct wp_security_context_manager_v1 **out = data;

	if (strcmp(interface, wp_security_context_manager_v1_interface.name) == 0) {
		*out = wl_registry_bind (registry, name, &wp_security_context_manager_v1_interface, 1);
	}
}

static void registry_handle_global_remove(void *data, struct wl_registry *registry, uint32_t name) {
	/* no-op */
}

static const struct wl_registry_listener registry_listener = {
	.global = registry_handle_global,
	.global_remove = registry_handle_global_remove,
};

int main(int argc, char **argv) {
	struct wl_display *display = NULL;
	struct wl_registry *registry = NULL;
	struct wp_security_context_manager_v1 *security_context_manager = NULL;
	struct wp_security_context_v1 *security_context = NULL;
	struct sockaddr_un sockaddr = {0};
	char *socket_path = NULL, *new_socket_path = NULL;

	int ret = 1;
	int pidfd = -1;
	int listen_fd = -1;
	int sync_fds[2];

	if (argc <= 1) {
		return 1;
	}

	argv++;
	argc--;
	argv[argc] = (char *) NULL;

	socket_path = get_wl_socket();
	if (!socket_path) {
		fprintf(stderr, "Failed to get wayland socket\n");
		goto out;
	}

	display = wl_display_connect(socket_path);
	if (!display) {
		fprintf(stderr, "Failed to create display\n");
		goto out;
	}

	registry = wl_display_get_registry(display);
	wl_registry_add_listener(registry, &registry_listener, &security_context_manager);
	ret = wl_display_roundtrip(display);
	wl_registry_destroy(registry);
	if (ret < 0) {
		fprintf(stderr, "wl_display_roundtrip() failed\n");
		goto out;
	}

	if (!security_context_manager) {
		fprintf(stderr, "Failed to create security_context_manager\n");
		goto out;
	}

	char *template = strdup("/dev/shm/wayland-XXXXXX");
	if (template == NULL) {
		perror("strdup");
		goto out;
	}
	new_socket_path = create_wl_socket(template);
	if (!new_socket_path) {
		perror("Failed to create wayland socket");
		goto out;
	}

	if (unlink(new_socket_path) != 0) {
		perror("Failed to unlink wayland socket");
		goto out;
	}

	listen_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (listen_fd < 0) {
		perror("socket");
		goto out;
	}

	sockaddr.sun_family = AF_UNIX;
	snprintf(sockaddr.sun_path, sizeof(sockaddr.sun_path), "%s", new_socket_path);
	if (bind(listen_fd, (struct sockaddr*) &sockaddr, sizeof(sockaddr)) != 0) {
		perror("bind");
		goto out;
	}
	if (listen(listen_fd, 0) != 0) {
		perror("listen");
		goto out;
	}

	if (pipe2(sync_fds, O_CLOEXEC) < 0) {
		perror("pipe2");
		goto out;
	}

	security_context = wp_security_context_manager_v1_create_listener(security_context_manager, listen_fd, sync_fds[1]);
	wp_security_context_v1_set_sandbox_engine(security_context, "wl-security-context");
	wp_security_context_v1_set_app_id(security_context, basename(argv[0]));
	wp_security_context_v1_commit(security_context);
	wp_security_context_v1_destroy(security_context);
	if (wl_display_roundtrip(display) < 0) {
		fprintf(stderr, "wl_display_roundtrip() failed\n");
		goto out;
	}

	ret = 0;

out:
	if (listen_fd >= 0) {
		close(listen_fd);
	}
	if (security_context_manager) {
		wp_security_context_manager_v1_destroy(security_context_manager);
	}
	if (display) {
		wl_display_disconnect(display);
	}

	if (ret) {
		return ret;
	}

	pidfd = pidfd_open(getpid(), 0);
	if (pidfd == -1) {
		perror("pidfd_open");
		goto out;
	}

	int child = fork();
	if (child == -1) {
		perror("fork");
		return 1;
	}
	if (child != 0) {
		uid_t uid;
		gid_t gid;
		int uid_map_fd = -1, gid_map_fd = -1;
		int uid_buf_size = -1 , gid_buf_size = -1;
		char *uid_buf = NULL, *gid_buf = NULL;
		int setgroups_fd = -1;

		uid = getuid();
		gid = getgid();

		if (unshare(CLONE_NEWUSER|CLONE_NEWNS)) {
			perror("unshare");
			return 1;
		}

		uid_buf_size = asprintf(&uid_buf, "%d %d 1", uid, uid);
		if (uid_buf_size < 0) {
			fprintf(stderr, "asprintf() failed\n");
			return 1;
		}
		uid_map_fd = open("/proc/self/uid_map", O_WRONLY);
		if (uid_map_fd < 0) {
			perror("open");
			return 1;
		}
		if (write_to_fd(uid_map_fd, uid_buf, uid_buf_size)) {
			perror("write uid map failed");
			return 1;
		}
		close(uid_map_fd);

		setgroups_fd = open("/proc/self/setgroups", O_WRONLY);
		if (setgroups_fd < 0) {
			perror("open");
			return 1;
		}
		if (write_to_fd(setgroups_fd, "deny", 4)) {
			perror("write setgroups failed");
			return 1;
		}
		close(setgroups_fd);

		gid_buf_size = asprintf(&gid_buf, "%d %d 1", gid, gid);
		if (gid_buf_size < 0) {
			fprintf(stderr, "asprintf() failed\n");
			return 1;
		}
		gid_map_fd = open("/proc/self/gid_map", O_WRONLY);
		if (gid_map_fd < 0) {
			perror("open");
			return 1;
		}
		if (write_to_fd(gid_map_fd, gid_buf, gid_buf_size)) {
			perror("write gid map failed");
			return 1;
		}
		close(gid_map_fd);

		if (mount("none", "/", NULL, MS_REC | MS_PRIVATE, NULL)) {
			perror("mount --make-private");
			return 1;
		}

		if (mount(new_socket_path, socket_path, NULL, MS_BIND, NULL)) {
			perror("mount");
			return 1;
		}

		if (execvp(argv[0], argv) != 0) {
			return 1;
		}
	} else {
		if (setsid() == -1 ) {
			perror("setsid");
			return 1;
		}
		struct pollfd fds[] = {
			{
				.fd = pidfd,
				.events = POLLIN,
			},
		};
		for (;;) {
			if (poll(fds, 1, -1) > 0) {
				break;
			}
			if (errno != EINTR) {
				perror("poll");
				return 1;
			}
		}
		close(sync_fds[0]);
		if (unlink(new_socket_path) != 0) {
			perror("Failed to clean up wayland socket");
			return 1;
		}
		return 0;
	}
}

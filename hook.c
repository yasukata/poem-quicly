/*
 *
 * Copyright 2022 Kenichi Yasukata
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#define __do_read(_fd, _buf, _count, _timeout) \
	({ \
		int __ret = 0, _r; \
		fd_set _set; \
		struct timeval _tv = { .tv_sec = (_timeout) }; \
		FD_ZERO(&_set); \
		FD_SET((_fd), &_set); \
		if ((_timeout) == -1) \
			assert((_r = select((_fd) + 1, &_set, NULL, NULL, NULL)) != -1); \
		else \
			assert((_r = select((_fd) + 1, &_set, NULL, NULL, &_tv)) != -1); \
		if (_r == 0) { \
			if ((_timeout) == 0) \
				__ret = -EAGAIN; \
			else \
				__ret = -ETIMEDOUT; \
		 } else { \
			ssize_t __rx; \
			assert((__rx = read((_fd), (_buf), (_count))) != 0); \
			if (__rx == -1) { \
				__ret = errno; \
				assert(__ret == EPIPE || __ret == ECONNRESET); \
			} else \
				assert(__rx == (ssize_t) (_count)); \
		} \
		__ret; \
	})

struct __hook_fd {
	char used;
	int accept_fd;
	struct sockaddr_storage sa;
	socklen_t addrlen;
	struct sockaddr_storage peer_sa;
	socklen_t peer_addrlen;
};

struct __sock_arg {
	int domain;
	int type;
	int protocol;
};

static const char *hook_unix_sock_path = NULL;
static char accept_lock_path[PATH_MAX] = { 0 };

#define MAX_SOCK_ARGS (4096)
static int sock_arg_cnt = 0;
static struct __sock_arg  sock_args[MAX_SOCK_ARGS];

static struct __hook_fd hfds[MAX_FD] = { 0 };

static int sock_hook_syscall_getpeername(int, struct sockaddr *, socklen_t *);

static int sock_hook_syscall_close(int fd)
{
	if (hfds[fd].accept_fd)
		close(hfds[fd].accept_fd);
	memset(&hfds[fd], 0, sizeof(hfds[fd]));
	close(fd);
	return 0;
}

static int sock_hook_syscall_socket(int domain, int type, int protocol)
{
	int fd, i;

	for (i = 0; i < sock_arg_cnt; i++) {
		if ((sock_args[i].domain == domain) &&
				(sock_args[i].type == type) &&
				(sock_args[i].protocol == protocol))
			goto redirect;
	}

	return socket(domain, type, protocol);

redirect:
	assert((fd = socket(AF_LOCAL, SOCK_STREAM, 0)) != -1);

	{
		struct sockaddr_un sun = { 0 };
		snprintf(sun.sun_path, sizeof(sun.sun_path), "%s", hook_unix_sock_path);
		sun.sun_family = AF_LOCAL;
		assert(!connect(fd, (const struct sockaddr *) &sun, sizeof(sun)));
	}

	assert(send(fd, &type, sizeof(type), MSG_NOSIGNAL) == sizeof(type));

	hfds[fd].used = 1;

	return fd;

}

static long sock_hook_syscall_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	long op = __NR_connect, ret;
	assert(send(sockfd, &op, sizeof(op), MSG_NOSIGNAL) == sizeof(op));
	assert(send(sockfd, &addrlen, sizeof(addrlen), MSG_NOSIGNAL) == sizeof(addrlen));
	assert(send(sockfd, addr, addrlen, MSG_NOSIGNAL) == addrlen);
	__do_read(sockfd, &ret, sizeof(ret), -1);
	return ret;
}

static long sock_hook_syscall_accept4(int sockfd, struct sockaddr *addr,
				   socklen_t *addrlen, int flags)
{
	long fd;
	int lock_fd;
	struct sockaddr_in _sin;

	assert(hfds[sockfd].accept_fd);

again:
	lock_fd = open(accept_lock_path, O_CREAT | O_EXCL, 0644);
	if (lock_fd == -1) {
		assert(errno == EEXIST);
		usleep(1);
		goto again;
	}

	if (__do_read(sockfd, &_sin, sizeof(_sin), (fcntl(sockfd, F_GETFL) & O_NONBLOCK) ? 0 : -1)) {
		close(lock_fd);
		assert(!unlink(accept_lock_path));
		return -EAGAIN;
	}

	if (addrlen) {
		socklen_t l = sizeof(_sin);
		if (*addrlen < l)
			l = *addrlen;
		memcpy(addr, &_sin, l);
		*addrlen = sizeof(_sin);
	}

	assert((fd = accept4(hfds[sockfd].accept_fd, NULL, 0, flags)) != -1);

	close(lock_fd);
	assert(!unlink(accept_lock_path));

	hfds[fd].used = 1;

	return fd;
}

static long sock_hook_syscall_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	return sock_hook_syscall_accept4(sockfd, addr, addrlen, 0);
}

static long sock_hook_syscall_recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen)
{
	ssize_t rx = recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
	if (addrlen)
		assert(!sock_hook_syscall_getpeername(sockfd, src_addr, addrlen));
	return rx;
}

static ssize_t sock_hook_syscall_sendmsg(int sockfd, const struct msghdr *msg, int flags)
{
	size_t i;
	ssize_t tx = 0;
	for (i = 0; i < msg->msg_iovlen; i++) {
		ssize_t _tx = sendto(sockfd,
				msg->msg_iov[i].iov_base,
				msg->msg_iov[i].iov_len,
				flags, NULL, 0);
		if (_tx == -1) {
			tx = -errno;
			break;
		}
		tx += _tx;
	}
	return tx;
}

static long sock_hook_syscall_recvmsg(int sockfd, struct msghdr *msg, int flags)
{
	ssize_t rx = recvmsg(sockfd, msg, flags);
	if (msg->msg_namelen)
		assert(!sock_hook_syscall_getpeername(sockfd, msg->msg_name, &msg->msg_namelen));
	return rx;
}

static int sock_hook_syscall_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	long op = __NR_bind, ret;
	assert(send(sockfd, &op, sizeof(op), MSG_NOSIGNAL) == sizeof(op));
	assert(send(sockfd, &addrlen, sizeof(addrlen), MSG_NOSIGNAL) == sizeof(addrlen));
	assert(send(sockfd, addr, addrlen, MSG_NOSIGNAL) == addrlen);
	__do_read(sockfd, &ret, sizeof(ret), -1);
	if (!ret) {
		assert(addrlen <= sizeof(hfds[sockfd].sa));
		memcpy(&hfds[sockfd].sa, addr, addrlen);
	}
	return ret;
}

static int sock_hook_syscall_listen(int sockfd, int backlog)
{
	long op = __NR_listen;
	long sock_id = sockfd;
	struct sockaddr_un sun = { 0 };

	if (hfds[sockfd].accept_fd) {
		D("try to listen again %d", sockfd);
		return 0;
	}

	assert((hfds[sockfd].accept_fd = socket(AF_LOCAL, SOCK_STREAM, 0)) != -1);
	snprintf(sun.sun_path, sizeof(sun.sun_path), "%s-accept-%ld", hook_unix_sock_path, sock_id);
	sun.sun_family = AF_LOCAL;
	unlink_unixsock_file(sun.sun_path);
	assert(!bind(hfds[sockfd].accept_fd, (const struct sockaddr *) &sun, sizeof(sun)));
	assert(!listen(hfds[sockfd].accept_fd, backlog));

	assert(send(sockfd, &op, sizeof(op), MSG_NOSIGNAL) == sizeof(op));
	assert(send(sockfd, &sock_id, sizeof(sock_id), MSG_NOSIGNAL) == sizeof(sock_id));

	return 0;
}

static int sock_hook_syscall_getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	if (addrlen) {
		socklen_t l = (*addrlen < hfds[sockfd].addrlen ? *addrlen : hfds[sockfd].addrlen);
		*addrlen = hfds[sockfd].addrlen;
		memcpy(addr, &hfds[sockfd].sa, l);
	}
	return 0;
}

static int sock_hook_syscall_getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	if (addrlen) {
		socklen_t l = (*addrlen < hfds[sockfd].peer_addrlen ? *addrlen : hfds[sockfd].peer_addrlen);
		*addrlen = hfds[sockfd].peer_addrlen;
		memcpy(addr, &hfds[sockfd].peer_sa, l);
	}
	return 0;
}

static long __sock_hook_syscall(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	long ret;
	switch (a1) {
	case __NR_read: // 0
		ret = read((int) a2, (void *) a3, (size_t) a4);
		if (ret < 0)
			ret = -errno;
		break;
	case __NR_write: // 1
		ret = send((int) a2, (const void *) a3, (size_t) a4, MSG_NOSIGNAL);
		if (ret < 0)
			ret = -errno;
		break;
	case __NR_close: // 3
		ret = sock_hook_syscall_close((int) a2);
		break;
	case __NR_ioctl: // 16
		ret = ioctl((int) a2, a3, a4, a5, a6, a7);
		if (ret < 0)
			ret = -errno;
		break;
	case __NR_connect: // 42
		ret = sock_hook_syscall_connect((int) a2, (const struct sockaddr *) a3, (socklen_t) a4);
		break;
	case __NR_accept: // 43
		ret = sock_hook_syscall_accept((int) a2, (struct sockaddr *) a3, (socklen_t *) a4);
		break;
	case __NR_sendto: // 44
		ret = sendto((int) a2, (const void *) a3, (size_t) a4, (int) a5, (const struct sockaddr *) a6, (socklen_t) a7);
		if (ret < 0)
			ret = -errno;
		break;
	case __NR_recvfrom: // 45
		ret = sock_hook_syscall_recvfrom((int) a2, (void *) a3, (size_t) a4, (int) a5, (struct sockaddr *) a6, (socklen_t *) a7);
		break;
	case __NR_sendmsg: // 46
		ret = sock_hook_syscall_sendmsg((int) a2, (const struct msghdr *) a3, (int) a4);
		break;
	case __NR_recvmsg: // 47
		ret = sock_hook_syscall_recvmsg((int) a2, (struct msghdr *) a3, (int) a4);
		break;
	case __NR_bind: // 49
		ret = sock_hook_syscall_bind((int) a2, (const struct sockaddr *) a3, (socklen_t) a4);
		break;
	case __NR_listen: // 50
		ret = sock_hook_syscall_listen((int) a2, (int) a3);
		break;
	case __NR_getsockname:	// 51
		ret = sock_hook_syscall_getsockname((int) a2, (struct sockaddr *) a3, (socklen_t *) a4);
		break;
	case __NR_getpeername: // 52
		ret = sock_hook_syscall_getpeername((int) a2, (struct sockaddr *) a3, (socklen_t *) a4);
		break;
	case __NR_setsockopt: // 54
		// TODO: implement this
		ret = 0;
		break;
	case __NR_getsockopt: // 55
		// TODO: implement this
		ret = 0;
		break;
	case __NR_fcntl: // 72
		ret = fcntl((int) a2, (int) a3, a4, a5, a6, a7);
		if (ret < 0)
			ret = -errno;
		break;
	case __NR_accept4: // 288
		ret = sock_hook_syscall_accept4((int) a2, (struct sockaddr *) a3, (socklen_t *) a4, (int) a5);
		break;
	default:
		E("unhandled syscall %ld", a1);
		ret = -1;
		assert(0);
		break;
	}
	return ret;
}

static bool our_fd(int fd)
{
	return (((0 <= fd) && (fd < MAX_FD)) && (hfds[fd].used != 0));
}

static long sock_hook_syscall(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	long ret;
	switch (a1) {
	case __NR_socket:	// 41
		ret = sock_hook_syscall_socket((int) a2, (int) a3, (int) a4);
		break;
	case __NR_read:		// 0
	case __NR_write:	// 1
	case __NR_close:	// 3
	case __NR_ioctl:	// 16
	case __NR_connect:	// 42
	case __NR_accept:	// 43
	case __NR_sendto:	// 44
	case __NR_recvfrom:	// 45
	case __NR_sendmsg:	// 46
	case __NR_recvmsg:	// 47
	case __NR_bind:		// 49
	case __NR_listen:	// 50
	case __NR_getsockname:	// 51
	case __NR_getpeername:	// 52
	case __NR_setsockopt:	// 54
	case __NR_getsockopt:	// 55
	case __NR_fcntl:	// 72
	case __NR_accept4:	// 288
		if (our_fd((int) a2)) {
			ret = __sock_hook_syscall(a1, a2, a3, a4, a5, a6, a7);
			break;
		}
		/* fall through */
	default:
		ret = syscall(a1, a2, a3, a4, a5, a6, a7);
		if (ret == -1)
			ret = -errno;
		break;
	}
	return ret;
}

static void parse_sock_arg(struct __sock_arg *sa, const char *arg_str)
{
	/* assuming format: domain,type,protocol */
	char *_arg;
	assert((_arg = strdup(arg_str)) != NULL);
	{
		size_t i, j, cnt, l = strlen(_arg);
		for (i = 0, j = 0, cnt = 0; j < l && cnt < 2; j++) {
			if (_arg[j] == ',') {
				_arg[j] = '\0';
				switch (cnt) {
				case 0:
					sa->domain = atoi(&_arg[i]);
					break;
				case 1:
					sa->type = atoi(&_arg[i]);
					break;
				}
				i = j + 1;
				cnt++;
			}
		}
		sa->protocol = atoi(&_arg[i]);
	}
	free(_arg);
}

static int sock_hook_init(void *sys_call_hook_ptr)
{
	int argc;
	char **argv;
	char *arg_str;

	parse_arg(HOOK_ENV_PATH, &argc, &argv, &arg_str);

	{
		int ch;
		optind = 1;
		while ((ch = getopt(argc, argv, "q:u:")) != -1) {
			switch (ch) {
			case 'q':
				assert(sock_arg_cnt < MAX_SOCK_ARGS);
				parse_sock_arg(&sock_args[sock_arg_cnt], optarg);
				D("sock hook: socket( domain %d, type %d, protocol %d )",
						sock_args[sock_arg_cnt].domain,
						sock_args[sock_arg_cnt].type,
						sock_args[sock_arg_cnt].protocol);
				sock_arg_cnt++;
				break;
			case 'u':
				hook_unix_sock_path = optarg;
				break;
			default:
				assert(0);
				break;
			}
		}
	}

	assert(sock_arg_cnt > 0);
	assert(hook_unix_sock_path);

	D("sock hook: unix socket path: %s", hook_unix_sock_path);

	assert(snprintf(accept_lock_path, sizeof(accept_lock_path), "%s-%d-accept-lock", hook_unix_sock_path, getpid()) != sizeof(accept_lock_path));
	{
		struct stat s = { 0 };
		if (stat(accept_lock_path, &s) == -1) // ensure to fail
			assert(errno == ENOENT); // must not exist
		else
			assert(0);
	}

	*((uintptr_t *) sys_call_hook_ptr) = (uintptr_t) sock_hook_syscall;

	return 0;
}

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

#include <openssl/pem.h>

#include <picotls.h>
#include <picotls/openssl.h>
#include <quicly.h>
#include <quicly/defaults.h>
#include <quicly/streambuf.h>

struct __server_fd {
	pthread_t me;
	char wait_connect;
	char is_connected;
	char is_bound;
	char is_accepted;
	char close_posted;
	quicly_conn_t *conn;
};

static struct __server_fd sfds[MAX_FD] = { 0 };

static const char *quicly_cert_file = NULL, *quicly_key_file = NULL, *server_unix_sock_path = NULL;

static volatile bool server_ready = false;

static void on_closed_by_remote(quicly_closed_by_remote_t *self __attribute__((unused)),
				quicly_conn_t *conn_,
				int err __attribute__((unused)),
				uint64_t frame_type __attribute__((unused)),
				const char *reason __attribute__((unused)),
				size_t reason_len __attribute__((unused)))
{
	int i;
	for (i = 0; i < MAX_FD; i++) {
		if (sfds[i].conn == conn_)
			break;
	}
	assert(sfds[i].me == pthread_self());
	assert(i != MAX_FD);
	sfds[i].close_posted = 1;
}

static void on_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len)
{
	int i;
	ptls_iovec_t input;
	if (quicly_streambuf_ingress_receive(stream, off, src, len) != 0)
		return;
	for (i = 0; i < MAX_FD; i++) {
		if (sfds[i].conn == stream->conn)
			break;
	}
	assert(sfds[i].me == pthread_self());
	assert(i != MAX_FD);
	input = quicly_streambuf_ingress_get(stream);
	if (input.len) {
		ssize_t tx = send(i, (const char *) input.base, input.len, MSG_NOSIGNAL);
		if (tx != -1) {
			assert(tx == (ssize_t) input.len);
			quicly_streambuf_ingress_shift(stream, input.len);
		} else {
			assert(errno == ECONNRESET || errno == EPIPE);
			sfds[i].close_posted = 1;
		}
	}
}

static int on_stream_open(quicly_stream_open_t *self __attribute__((unused)),
			  quicly_stream_t *stream)
{
	static const quicly_stream_callbacks_t stream_callback = {
		.on_destroy = quicly_streambuf_destroy,
		.on_send_shift = quicly_streambuf_egress_shift,
		.on_send_emit = quicly_streambuf_egress_emit,
		.on_receive = on_receive,
		.on_send_stop = quicly_stream_noop_on_send_stop,
		.on_receive_reset = quicly_stream_noop_on_receive_reset,
	};
	assert(!quicly_streambuf_create(stream, sizeof(quicly_streambuf_t)));
	stream->callbacks = &stream_callback;
	return 0;
}

static void *quicly_socket_thread(void *data)
{
	int udp_fd, epoll_fd, fd = (int)((uintptr_t) data);
	long listen_sock_id = -1;
	bool should_stop = false;

	quicly_conn_t *conn[MAX_FD] = { 0 };
	quicly_cid_plaintext_t next_cid;
	ptls_openssl_sign_certificate_t sign_certificate;
	quicly_stream_open_t stream_open = { on_stream_open };
	quicly_closed_by_remote_t closed_by_remote = { on_closed_by_remote };
	quicly_context_t ctx = quicly_spec_context;

	ptls_context_t tlsctx = {
		.random_bytes = ptls_openssl_random_bytes,
		.get_time = &ptls_get_time,
		.key_exchanges = ptls_openssl_key_exchanges,
		.cipher_suites = ptls_openssl_cipher_suites,
	};

	ctx.tls = &tlsctx;
	quicly_amend_ptls_context(ctx.tls);
	ctx.stream_open = &stream_open;
	ctx.closed_by_remote = &closed_by_remote;

	{
		EVP_PKEY *pkey;
		FILE *fp;
		assert(!ptls_load_certificates(&tlsctx, quicly_cert_file));
		assert((fp = fopen(quicly_key_file, "r")) != NULL);
		assert((pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL)) != NULL);
		fclose(fp);
		ptls_openssl_init_sign_certificate(&sign_certificate, pkey);
		EVP_PKEY_free(pkey);
	}
	tlsctx.sign_certificate = &sign_certificate.super;

	assert((epoll_fd = epoll_create1(EPOLL_CLOEXEC)) != -1);

	assert((udp_fd = socket(AF_INET, SOCK_DGRAM, 0)) != -1);

	{
		int on = 1;
		assert(setsockopt(udp_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) != -1);
	}
	{
		int on = 1;
		assert(setsockopt(udp_fd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on)) != -1);
	}

	{
		struct epoll_event ev = {
			.events = EPOLLIN,
			.data.fd = udp_fd,
		};
		assert(!epoll_ctl(epoll_fd, EPOLL_CTL_ADD, ev.data.fd, &ev));
	}
	{
		struct epoll_event ev = {
			.events = EPOLLIN,
			.data.fd = fd,
		};
		assert(!epoll_ctl(epoll_fd, EPOLL_CTL_ADD, ev.data.fd, &ev));
	}

	while (!should_stop) {
		int i, nfd;
		struct epoll_event evts[256];
		long timeout, t = INT64_MAX;

		for (i = 0; conn[i] != NULL; i++) {
			long _t = quicly_get_first_timeout(conn[i]);
			if (_t < t)
				t = _t;
		}
		timeout = t - ctx.now->cb(ctx.now);
		if (timeout < 0)
			timeout = 0;
		if (100 < timeout)
			timeout = 100;

		nfd = epoll_wait(epoll_fd, evts, 256, timeout);
		assert(nfd >= 0);
		for (i = 0; i < nfd; i++) {
			if (evts[i].data.fd == udp_fd) {
				uint8_t buf[4096];
				struct sockaddr_storage sa = { 0 };
				struct iovec vec = {
					.iov_base = buf,
					.iov_len = sizeof(buf),
				};
				struct msghdr msg = {
					.msg_name = &sa,
					.msg_namelen = sizeof(sa),
					.msg_iov = &vec,
					.msg_iovlen = 1,
				};
				ssize_t rx = recvmsg(udp_fd, &msg, 0);
				if (rx > 0) {
					size_t off = 0;
					while (off < (size_t) rx) {
						int j;
						quicly_decoded_packet_t decoded;
						if (quicly_decode_packet(&ctx, &decoded, msg.msg_iov[0].iov_base, rx, &off) == SIZE_MAX)
							break;
						for (j = 0; j < MAX_FD; j++) {
							if (conn[j]) {
								if (quicly_is_destination(conn[j], NULL, msg.msg_name, &decoded))
									break;
							}
						}
						if (j != MAX_FD) {
							int ret = quicly_receive(conn[j], NULL, msg.msg_name, &decoded);
							assert(ret == 0 || ret == QUICLY_ERROR_PACKET_IGNORED);
							if (sfds[j].wait_connect && quicly_connection_is_ready(conn[j])) {
								long val = 0;
								assert(sfds[j].me == pthread_self());
								sfds[j].wait_connect = 0;
								sfds[j].is_connected = 1;
								assert(write(j, &val, sizeof(val)) == sizeof(val));
							}
							if (ret != QUICLY_ERROR_PACKET_IGNORED && sfds[j].close_posted)
								quicly_close(conn[j], QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0), "");
						} else if (listen_sock_id != -1) {
							quicly_conn_t *newconn;
							if (!quicly_accept(&newconn, &ctx, NULL, msg.msg_name, &decoded, NULL, &next_cid, NULL)) {
								int newfd;
								assert((newfd = socket(AF_LOCAL, SOCK_STREAM, 0)) != -1);
								{
									struct sockaddr_un sun = { .sun_family = AF_LOCAL, };
									snprintf(sun.sun_path, sizeof(sun.sun_path), "%s-accept-%ld", server_unix_sock_path, listen_sock_id);
									assert(!connect(newfd, (const struct sockaddr *) &sun, sizeof(sun)));
								}
								conn[newfd] = newconn;
								sfds[newfd].conn = newconn;
								sfds[newfd].me = pthread_self();
								{
									struct epoll_event ev = {
										.events = EPOLLIN,
										.data.fd = newfd,
									};
									assert(!epoll_ctl(epoll_fd, EPOLL_CTL_ADD, ev.data.fd, &ev));
								}
								sfds[newfd].is_accepted = 1;
								assert(msg.msg_namelen == sizeof(struct sockaddr_in)); // FIXME
								assert(write(fd, msg.msg_name, msg.msg_namelen) == msg.msg_namelen);
							}
						}
					}
				}
			} else {
				ssize_t rx;
				if (sfds[evts[i].data.fd].close_posted) {
					// pass
				} else if (sfds[evts[i].data.fd].is_connected || sfds[evts[i].data.fd].is_accepted) {
					quicly_stream_t *stream;
					assert(quicly_connection_is_ready(conn[evts[i].data.fd]));
					assert(!quicly_get_or_open_stream(conn[evts[i].data.fd], 0, &stream));
					assert(stream);
					assert(quicly_sendstate_is_open(&stream->sendstate));
					{
						char b[1200] = { 0 };
						rx = recv(evts[i].data.fd, b, sizeof(b), MSG_DONTWAIT);
						if (rx > 0)
							assert(!quicly_streambuf_egress_write(stream, b, rx));
						else if (errno != EAGAIN)
							goto sock_error;
					}
				} else {
					/* operations requested through syscalls */
					long op;
					rx = read(evts[i].data.fd, &op, sizeof(op));
					if (rx <= 0) {
sock_error:
						/* socket is closed */
						if (rx == -1)
							assert(errno == ECONNRESET);
						else
							assert(!rx);
						if (evts[i].data.fd == fd)
							should_stop = true;
						else {
							struct epoll_event ev = {
								.events = EPOLLIN,
								.data.fd = evts[i].data.fd,
							};
							assert(!epoll_ctl(epoll_fd, EPOLL_CTL_DEL, ev.data.fd, &ev));
						}
						sfds[evts[i].data.fd].close_posted = 1;
						if (conn[evts[i].data.fd])
							quicly_close(conn[evts[i].data.fd], QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0), "");
					} else {
						switch (op) {
						case __NR_connect:
							{
								struct sockaddr_storage addr;
								socklen_t addrlen;
								assert(read(evts[i].data.fd, &addrlen, sizeof(addrlen)) == sizeof(addrlen));
								assert(addrlen <= sizeof(struct sockaddr_storage));
								assert(read(evts[i].data.fd, &addr, addrlen) == addrlen);
								sfds[evts[i].data.fd].wait_connect = 1;

								assert(!connect(udp_fd, (const struct sockaddr *) &addr, addrlen));

								assert(!quicly_connect(&conn[evts[i].data.fd], &ctx, "localhost",
											(struct sockaddr *) &addr, NULL, &next_cid,
											ptls_iovec_init(NULL, 0), NULL, NULL));
								assert(!sfds[evts[i].data.fd].conn);
								sfds[evts[i].data.fd].conn = conn[evts[i].data.fd];
								sfds[evts[i].data.fd].me = pthread_self();
								{
									quicly_stream_t *stream;
									assert(!quicly_open_stream(conn[evts[i].data.fd], &stream, 0));
								}
							}
							break;
						case __NR_bind:
							{
								long ret;
								struct sockaddr_storage addr;
								socklen_t addrlen;
								assert(read(evts[i].data.fd, &addrlen, sizeof(addrlen)) == sizeof(addrlen));
								assert(addrlen <= sizeof(struct sockaddr_storage));
								assert(read(evts[i].data.fd, &addr, addrlen) == addrlen);
								ret = bind(udp_fd, (const struct sockaddr *) &addr, addrlen);
								sfds[evts[i].data.fd].is_bound = 1;
								assert(write(evts[i].data.fd, &ret, sizeof(ret)) == sizeof(ret));
							}
							break;
						case __NR_listen:
							{
								long sock_id = -1;
								assert(read(evts[i].data.fd, &sock_id, sizeof(sock_id)) == sizeof(sock_id));
								assert(listen_sock_id == -1 || listen_sock_id == sock_id);
								listen_sock_id = sock_id;
							}
							break;
						default:
							E("unknown op %ld", op);
							assert(0);
							break;
						}
					}
				}
			}
		}
		/* send packet */
		{
			int i;
			for (i = 0; i < MAX_FD; i++) {
				int ret;
				quicly_address_t dest, src;
				struct iovec dgrams[10];
				uint8_t dgrams_buf[PTLS_ELEMENTSOF(dgrams) * ctx.transport_params.max_udp_payload_size];
				size_t num_dgrams = PTLS_ELEMENTSOF(dgrams);
				if (!conn[i])
					continue;
				ret = quicly_send(conn[i], &dest, &src, dgrams, &num_dgrams, dgrams_buf, sizeof(dgrams_buf));
				switch (ret) {
				case 0:
					{
						unsigned int j;
						for (j = 0; j < num_dgrams; j++) {
							struct msghdr msg = {
								.msg_name = &dest.sa,
								.msg_namelen = quicly_get_socklen(&dest.sa),
								.msg_iov = &dgrams[j],
								.msg_iovlen = 1,
							};
							assert(sendmsg(udp_fd, &msg, 0) != -1);
						}
					}
					break;
				case QUICLY_ERROR_FREE_CONNECTION:
					sfds[i].close_posted = 1;
					break;
				default:
					E("quicly_send failed %d", ret);
					assert(0);
					break;
				}
			}
		}
		{
			int i;
			for (i = 0; i < MAX_FD; i++) {
				if (sfds[i].close_posted && sfds[i].me == pthread_self()) {
					conn[i] = NULL;
					if (sfds[i].conn)
						quicly_free(sfds[i].conn);
					memset(&sfds[i], 0, sizeof(sfds[fd]));
					asm volatile ("" ::: "memory");
					close(i);
					if (i == fd)
						should_stop = true;
				}
			}
		}
	}

	close(udp_fd);
	close(epoll_fd);

	pthread_exit(NULL);
}

static void *quicly_thread_fn(void *data)
{
	int fd;

	assert((fd = socket(AF_LOCAL, SOCK_STREAM, 0)) != -1);

	unlink_unixsock_file(server_unix_sock_path);

	{
		struct sockaddr_un sun = { .sun_family = AF_LOCAL, };
		snprintf(sun.sun_path, sizeof(sun.sun_path), "%s", server_unix_sock_path);
		assert(!bind(fd, (const struct sockaddr *) &sun, sizeof(sun)));
	}

	assert(!listen(fd, MAX_FD));

	asm volatile ("" ::: "memory");

	*((volatile bool *) data) = true;

	while (1) {
		int newfd, type;
		pthread_t th;
		struct sockaddr_un sun;
		socklen_t addrlen = sizeof(sun);
		assert((newfd = accept(fd, (struct sockaddr *) &sun, &addrlen)) != -1);
		assert(read(newfd, &type, sizeof(type)) == sizeof(type));
		assert(!pthread_create(&th, NULL, quicly_socket_thread, (void *)((uintptr_t) newfd)));
	}

	close(fd);

	unlink_unixsock_file(server_unix_sock_path);
}

static int quicly_server_init(void)
{
	int argc;
	char **argv;
	char *arg_str;

	parse_arg(SERVER_ENV_PATH, &argc, &argv, &arg_str);

	{
		int ch;
		optind = 1;
		while ((ch = getopt(argc, argv, "c:hk:u:")) != -1) {
			switch (ch) {
			case 'c':
				quicly_cert_file = optarg;
				break;
			case 'h':
				goto print_usage;
			case 'k':
				quicly_key_file = optarg;
				break;
			case 'u':
				server_unix_sock_path = optarg;
				break;
			default:
				E("bad option %c %s", ch, optarg);
				assert(0);
				break;
			}
		}
	}

	D("quicly-server: cert file: %s", quicly_cert_file);
	D("quicly-server: key file: %s", quicly_key_file);
	D("quicly-server: unix socket path: %s", server_unix_sock_path);

	if (!quicly_cert_file || !quicly_key_file || !server_unix_sock_path) {
		printf("please spacify a cert file, a key file, and a path for the unix socket\n");
print_usage:
		printf("usage:\n\t-c cert_file\n\t-k key_file\n\t-u server_unix_sock_path\n");
		exit(1);
	}

	{
		pthread_t quicly_th;
		volatile bool thread_ready = false;
		assert(!pthread_create(&quicly_th, NULL, quicly_thread_fn, (void *) &thread_ready));
		while (!thread_ready)
			usleep(10000);
	}

	return 0;
}

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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#include <sys/file.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/epoll.h>
#include <sys/syscall.h>

#include <pthread.h>

#define D(fmt, ...) printf("\x1b[36m[%s:%u]: " fmt "\x1b[39m\n", __func__, __LINE__, ##__VA_ARGS__)
#define E(fmt, ...) printf("\x1b[31m[%s:%u]: " fmt "\x1b[39m\n", __func__, __LINE__, ##__VA_ARGS__)

#define MAX_FD (4096)

#define HOOK_ENV_PATH "QUICLY_HOOK_ARGS"
#define SERVER_ENV_PATH "QUICLY_SERVER_ARGS"

static void unlink_unixsock_file(const char *pathname)
{
	struct stat s = { 0 };
	if (stat(pathname, &s))
		assert(errno == ENOENT);
	else {
		assert((s.st_mode & S_IFMT) == S_IFSOCK);
		assert(!unlink(pathname));
	}
}

static void parse_arg(const char *envstr, int *argc, char ***argv, char **arg_str)
{
	int i, j = 0;
	size_t arg_str_len;
	bool prev_empty = true;

	*arg_str = strdup(getenv(envstr));
	arg_str_len = strlen(*arg_str);
	*argc = 1;

	for (i = 0; i < (int) arg_str_len; i++) {
		if ((*arg_str)[i] == ' ')
			prev_empty = true;
		else if (prev_empty) {
			(*argc)++;
			prev_empty = false;
		}

	}
	assert((*argv = (char **) malloc(sizeof(char *) * (*argc + 2))) != NULL);
	(*argv)[j++] = __FILE__;
	prev_empty = true;
	for (i = 0; i < (int) arg_str_len; i++) {
		if ((*arg_str)[i] == ' ') {
			prev_empty = true;
			(*arg_str)[i] = '\0';
		} else if (prev_empty) {
			(*argv)[j++] = &(*arg_str)[i];
			prev_empty = false;
		}
	}
	(*argv)[*argc + 1] = NULL;
}

#include "server.c"
#include "hook.c"

int __hook_init(long placeholder __attribute__((unused)),
		void *sys_call_hook_ptr)
{
	if (getenv(HOOK_ENV_PATH))
		assert(!sock_hook_init(sys_call_hook_ptr));

	if (getenv(SERVER_ENV_PATH))
		assert(!quicly_server_init());

	return 0;
}

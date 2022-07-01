PROGS = libpoem-quicly.so

CC = gcc

CLEANFILES = $(PROGS) *.o *.d

QUICLY_DIR ?= ./quicly
PICOTLS_DIR ?= ./picotls

NO_MAN=
CFLAGS = -O3 -pipe
CFLAGS += -g -rdynamic
CFLAGS += -Wall -Wunused-function
CFLAGS += -Wextra
CFLAGS += -I$(PICOTLS_DIR)/include -I$(QUICLY_DIR)/include
CFLAGS += -shared -fPIC

LDFLAGS += -lpthread -lcrypto -lm

C_SRCS = main.c

C_OBJS = $(C_SRCS:.c=.o)

OBJS = $(C_OBJS) \
	$(QUICLY_DIR)/libquicly.a \
	$(PICOTLS_DIR)/libpicotls-openssl.a \
	$(PICOTLS_DIR)/libpicotls-core.a

CLEANFILES += $(C_OBJS)

.PHONY: all
all: $(PROGS)

$(PICOTLS_DIR)/libpicotls-openssl.a:
$(PICOTLS_DIR)/libpicotls-core.a:
	cmake -E env CFLAGS="-fPIC" cmake --clean-first -H$(PICOTLS_DIR) -B$(PICOTLS_DIR) .
	make -C $(PICOTLS_DIR)

$(QUICLY_DIR)/libquicly.a:
	cmake -E env CFLAGS="-fPIC" cmake --clean-first -H$(QUICLY_DIR) -B$(QUICLY_DIR) .
	make -C $(QUICLY_DIR)

$(PROGS): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	-@rm -rf $(CLEANFILES)

CC ?= cc
PAM_CFLAGS = $(shell pkg-config --cflags pam)
PAM_LIBS = $(shell pkg-config --libs pam)
PAM_LIBDIR = $(shell pkg-config --variable=libdir pam)
SECURITY_DIR = $(PAM_LIBDIR)/security
INSTALL = install
RM = rm

.PHONY: all clean
default: all

clean:
	rm -f pam_gnupgdir.o pam_gnupgdir.so

pam_gnupgdir.o: pam_gnupgdir.c
	$(CC) -Wall -Wextra $(PAM_CFLAGS) -fPIC $(CFLAGS) -c pam_gnupgdir.c

pam_gnupgdir.so: pam_gnupgdir.o
	$(CC) -shared $(PAM_LIBS) $(LDLIBS) $(LDFLAGS) -o pam_gnupgdir.so pam_gnupgdir.o

all: pam_gnupgdir.so

install: pam_gnupgdir.so
	install -o 0 -g 0 -m 755 -t $(SECURITY_DIR) pam_gnupgdir.so

uninstall:
	rm -f $(SECURITY_DIR)/pam_gnupgdir.so

CFLAGS = -D_FORTIFY_SOURCE=2 -O1 -g -Werror
AM_CFLAGS = -std=gnu99 -Wall -W -Wno-missing-field-initializers -D_GNU_SOURCE \
 -Wno-unused-parameter $(AM_CFLAGS-y) $(CFLAGS_$(DIGEST_PROVIDER))
AM_LDFLAGS = -Wl,-as-needed

bin_PROGRAMS = stream-encode stream-decode

ENABLE_ZLIB = y

DIGEST_PROVIDER = gnutls
X509_PROVIDER = gnutls

AM_CFLAGS-$(ENABLE_ZLIB) += -DENABLE_ZLIB=1

COMPRESSION-y = compression.c compression.h
COMPRESSION-$(ENABLE_ZLIB) += compression-zlib.c

DECOMPRESSION-y = decompression.c decompression.h
DECOMPRESSION-$(ENABLE_ZLIB) += decompression-zlib.c

PKG_CONFIG ?= pkg-config
CFLAGS_gnutls = $(shell $(PKG_CONFIG) --cflags gnutls)
LIBS_gnutls = $(shell $(PKG_CONFIG) --libs gnutls)

LIBS = $(LIBS_$(DIGEST_PROVIDER)) $(LIBS_$(X509_PROVIDER)) $(LIBS-y)
LIBS-$(ENABLE_ZLIB) += -lz

stream-encode_SOURCES = \
	stream-encode.c \
	signature-$(DIGEST_PROVIDER).c \
	x509-$(X509_PROVIDER).c \
	$(COMPRESSION-y) \
	signature-none.c \
	signature.c \
	signature.h \
	stream.h \
	util.c \
	util.h \

stream-decode_SOURCES = \
	stream-decode.c \
	stream.h \
	signature-$(DIGEST_PROVIDER).c \
	x509-$(X509_PROVIDER).c \
	$(DECOMPRESSION-y) \
	signature-none.c \
	signature.c \
	signature.h \
	util.c \
	util.h \

progprefix =
progsuffix =

prefix = /usr/local
bindir = ${prefix}/bin

_bin_PROGRAMS = $(addsuffix $(progsuffix),$(addprefix $(progprefix),$(bin_PROGRAMS)))

all:	$(_bin_PROGRAMS)

.SECONDEXPANSION:
$(_bin_PROGRAMS):$(progprefix)%$(progsuffix):	$$($$*_SOURCES) Makefile
	$(CC) $(AM_CFLAGS) $(CFLAGS) $(AM_LDFLAGS) $(LDFLAGS) $(filter %.c,$^) -o $@ $(LIBS)


$(DESTDIR)$(bindir):
	install -d -m 0755 $@

install:	$(_bin_PROGRAMS) | $(DESTDIR)$(bindir)
	install -p -m 0755 $^ $(DESTDIR)$(bindir)/

clean:
	rm -f $(_bin_PROGRAMS)

.PHONY:	install all

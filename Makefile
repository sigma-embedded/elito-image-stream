CFLAGS = -D_FORTIFY_SOURCE=2 -O2 -g -Werror
AM_CFLAGS = -std=gnu99 -Wall -W -Wno-missing-field-initializers -D_GNU_SOURCE \
 -Wno-unused-parameter

bin_PROGRAMS = stream-encode stream-decode

stream-encode_SOURCES = \
	stream-encode.c \
	signature-kernel.c \
	signature-none.c \
	signature.c \
	stream.h \

stream-decode_SOURCES = \
	stream-decode.c \
	stream.h \
	signature-kernel.c \
	signature-none.c \
	signature.c \
	signature.h

progprefix =

prefix = /usr/local
bindir = ${prefix}/bin

_bin_PROGRAMS = $(addprefix $(progprefix),$(bin_PROGRAMS))

all:	$(_bin_PROGRAMS)

.SECONDEXPANSION:
$(_bin_PROGRAMS):$(progprefix)%:	$$($$*_SOURCES) Makefile
	$(CC) $(AM_CFLAGS) $(CFLAGS) $(AM_LDFLAGS) $(LDFLAGS) $(filter %.c,$^) -o $@ $(LIBS)


$(DESTDIR)$(bindir):
	install -d -m 0755 $@

install:	$(_bin_PROGRAMS) | $(DESTDIR)$(bindir)
	install -p -m 0755 $^ $(DESTDIR)$(bindir)/

clean:
	rm -f $(_bin_PROGRAMS)

.PHONY:	install all

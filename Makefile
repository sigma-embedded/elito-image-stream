CFLAGS = -D_FORTIFY_SOURCE=2 -O2 -g -Werror
AM_CFLAGS = -std=gnu99 -Wall -W -Wno-missing-field-initializers

bin_PROGRAMS = stream-encode stream-decode

progprefix =

prefix = /usr/local
bindir = ${prefix}/bin

_bin_PROGRAMS = $(addprefix $(progprefix),$(bin_PROGRAMS))

all:	$(_bin_PROGRAMS)

$(progprefix)%:	%.c stream.h Makefile
	$(CC) $(AM_CFLAGS) $(CFLAGS) $(AM_LDFLAGS) $(LDFLAGS) $< -o $@ $(LIBS)


$(DESTDIR)$(bindir):
	install -d -m 0755 $@

install:	$(_bin_PROGRAMS) | $(DESTDIR)$(bindir)
	install -p -m 0755 $^ $(DESTDIR)$(bindir)/

clean:
	rm -f $(_bin_PROGRAMS)

.PHONY:	install all

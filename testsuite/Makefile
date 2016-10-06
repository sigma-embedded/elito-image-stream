DIGEST_PROVIDERS = gnutls kernel
X509_PROVIDERS = gnutls noop

STREAM_TMPDIR ?= tmp

CFLAGS ?= -Wall -W -std=gnu99 -D_FORTIFY_SOURCE=2 -O2

all:	.stamps/ca .stamps/build .stamps/stream .stamps/tests

compile:	.stamps/build

clean:
	rm -rf .stamps ca bin tmp

.stamps bin:
	mkdir -p $@

.stamps/ca: | .stamps
	$(MAKE) _mode=ca init-ca CA_DIR=ca/valid
	$(MAKE) _mode=ca init-ca CA_DIR=ca/invalid
	touch $@

.stamps/%: FORCE | .stamps
	$(MAKE) _mode=$* $*

.stamps/stream: .stamps/build
.stamps/tests:	.stamps/stream .stamps/build

ifneq ($(_mode),)
include make-$(_mode).mk
endif

FORCE:
.PHONY:	FORCE

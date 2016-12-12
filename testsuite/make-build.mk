HOST_CC ?= $(CC)
HOST_CFLAGS ?= $(CFLAGS)

define init_variant
ENCODERS += bin/stream-encode_$1-$2
DECODERS += bin/stream-decode_$1-$2

bin/stream-encode_$1-$2 bin/stream-decode_$1-$2:	.build_$1-$2

.build_$1-$2:	FORCE | bin
	$(MAKE) -C .. -f ${abs_top_srcdir}/../Makefile progsuffix=_$1-$2 progprefix=$(abspath .)/bin/ DIGEST_PROVIDER=$1 X509_PROVIDER=$2
endef

$(foreach d,$(DIGEST_PROVIDERS),$(foreach x,$(X509_PROVIDERS),$(eval $(call init_variant,$d,$x))))

build:	$(ENCODERS) $(DECODERS) bin/gen-input bin/gremlin

bin/%:	%.c | bin
	$(HOST_CC) $(HOST_CFLAGS) $< -o $@

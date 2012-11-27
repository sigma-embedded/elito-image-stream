SIZES = 0 1 512 65536 271344 5242880
MODES = zero ff seq rnd

O := $(STREAM_TMPDIR)

_mode_sizes = $(foreach s,$(SIZES),$(foreach m,$(MODES),$m-$s))

IN_FILES = $(addprefix $O/,$(addsuffix .in,$(_mode_sizes)))

$O:
	mkdir -p $@

$(IN_FILES):$O/%.in:	bin/gen-input | $O
	@rm -f $@
	$(abspath $<) '$@' '$(SIZE)' '$(MODE)'

define gen-input
$O/$1-$2.in:	MODE=$1
$O/$1-$2.in:	SIZE=$2
endef 

stream:	$(IN_FILES)

$(foreach s,$(SIZES),$(foreach m,$(MODES),$(eval $(call gen-input,$m,$s))))

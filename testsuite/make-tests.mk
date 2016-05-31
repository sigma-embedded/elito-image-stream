I := $(STREAM_TMPDIR)
R  = runtest.sh

_genprog = \
$(if $(patsubst -%,,$2),\
$(if $(patsubst !%,,$2),\
$(if $(patsubst ~%,,$2),\
$1$2,\
~$1$(patsubst ~%,%,$2)),\
!$1$(patsubst !%,%,$2)),\
-$1$(patsubst -%,%,$2))\

genprog = $(strip $(foreach p,$2, $(call _genprog,$1,$p)))

run = @env BASE_ID=$(strip $1) bash $R \
  '$(call genprog,bin/stream-encode_,$2)' \
  '$(call genprog,bin/stream-decode_,$3)' \
  '$(addsuffix .in,$(addprefix $(STREAM_TMPDIR)/,$4))' \
  $5

x509 = sig=x509,key=ca/$1.key,crt=ca/$1.crt

c = ,
E_0 = 0x1,none
E_1 = 0x1,gzip,sha1
E_2 = 0x1,md5
E_3 = 0x1,sha256
E_4 = 0x1,sha512
E_5 = 0x1,
D_0 = --ca ca/valid/ca.crt --crl ca/valid/ca.crl
D_1 = $(D_0) --min-strength=100

tests:
	$(call run, 0, \
	       kernel-gnutls gnutls-gnutls, \
	       kernel-gnutls gnutls-gnutls, \
	       zero-0 zero-1 zero-65536 rnd-65536 rnd-5242880, \
	       '$(E_0)' '$(D_0)')

ifneq ($(SKIP_MD5),true)
	$(call run, 50, \
	       kernel-gnutls gnutls-gnutls, \
	       kernel-gnutls gnutls-gnutls, \
	       rnd-271344, \
	       '$(E_2)' '$(D_0)')
endif

	$(call run, 100, \
	       kernel-gnutls gnutls-gnutls, \
	       kernel-gnutls gnutls-gnutls, \
	       rnd-271344, \
	       '$(E_3)' '$(D_0)')

	$(call run, 150, \
	       kernel-gnutls gnutls-gnutls, \
	       kernel-gnutls gnutls-gnutls, \
	       rnd-271344, \
	       '$(E_4)' '$(D_0)')

	$(call run, 200, \
	       kernel-gnutls gnutls-gnutls, \
	       kernel-gnutls gnutls-gnutls, \
	       zero-0 zero-1 zero-65536 rnd-65536 rnd-5242880, \
	       '$(E_1)' '$(D_0)')

	$(call run, 250, \
	       !kernel-gnutls !gnutls-gnutls, \
	       -kernel-gnutls -gnutls-gnutls, \
	       zero-0 zero-1 zero-65536 rnd-65536 rnd-5242880, \
	       '$(E_1)' '$(D_0)')

	$(call run, 300, \
	       gnutls-gnutls, gnutls-gnutls, \
	       rnd-0 rnd-271344, \
	       '$(E_5)$(call x509,valid/ok)' '$(D_1)')

	$(call run, 310, \
	       gnutls-gnutls, gnutls-gnutls, \
	       rnd-0 rnd-271344, \
	       '$(E_5)zlib${c}$(call x509,valid/ok)' '$(D_1)')

	$(call run, 320, \
	       gnutls-gnutls, -gnutls-gnutls, \
	       rnd-271344, \
	       '$(E_5)$(call x509,valid/revoked)' '$(D_1)')

	$(call run, 330, \
	       gnutls-gnutls, -gnutls-gnutls, \
	       rnd-271344, \
	       '$(E_5)$(call x509,invalid/ok)' '$(D_1)')

	$(call run, 340, \
	       gnutls-gnutls, -gnutls-gnutls, \
	       rnd-271344, \
	       '$(E_5)$(call x509,valid/bad-usage)' '$(D_1)')

X509_CERTIFICATES = ok bad-usage revoked

X509_ENV_ca = \
  CN='Top Level CA' \
  KEY_USAGE='cRLSign, keyCertSign' \
  EXTENDED_KEY_USAGE=unused

X509_ENV_ok = \
  CN='ok' \
  KEY_USAGE=critical,digitalSignature \
  EXTENDED_KEY_USAGE=critical,codeSigning

X509_ENV_bad-usage = \
  CN='bad key usage' \
  KEY_USAGE=critical,digitalSignature \
  EXTENDED_KEY_USAGE=clientAuth

X509_ENV_revoked = $(X509_ENV_ok) \
  CN='revoked'


CA_REQ = user_cert
#CA_KEY_USAGE ?= digitalSignature
#CA_EXTENDED_KEY_USAGE ?= codeSigning

OPENSSL = openssl
OPENSSL_ENV = \
	WORKDIR='$(CA_DIR)' \
	REQ='$(CA_REQ)' \
	$(X509_ENV_$*) \

OPENSSL_X509 = env $(OPENSSL_ENV) $(OPENSSL) x509 \
	-req \
        -extfile '$(filter %.conf,$^)' \
	-in '$(filter %.req,$^)' \
	-signkey '$(filter %.key,$^)' \
	-out '$@'

OPENSSL_REQ = env $(OPENSSL_ENV) $(OPENSSL) req \
	-batch -new \
	-key '$(filter %.key,$^)' \
	-config '$(filter %.conf,$^)' \
	-out '$@'

OPENSSL_CA = env $(OPENSSL_ENV) $(OPENSSL) ca \
	-batch \
	-config '$(filter %.conf,$^)' \
	-in '$(filter %.req,$^)' \
	-out '$@'

OPENSSL_CRL = env $(OPENSSL_ENV) $(OPENSSL) ca \
	-batch -gencrl \
	-config '$(filter %.conf,$^)' \
	-out $(CA_DIR)/ca.crl

_certs = $(addsuffix .pem,$(addprefix $(CA_DIR)/,$(X509_CERTIFICATES)))

init-ca:	$(CA_DIR)/ca.pem $(_certs) $(CA_DIR)/revoked.revoke

gen-crl:
	$(OPENSSL_CRL)

$(CA_DIR)/%.revoke:	openssl.conf $(CA_DIR)/%.crt
	$(OPENSSL_CRL) -revoke '$(filter %.crt,$^)' -crl_reason unspecified
	$(OPENSSL_CRL)
	@touch $@

$(CA_DIR) $(CA_DIR)/.ca/newcerts:
	mkdir -p $@

$(CA_DIR)/.ca/index.txt: | $(CA_DIR)
	touch $@

$(CA_DIR)/.ca/serial: | $(CA_DIR)
	@rm -f $@
	echo 01 > $@

$(CA_DIR)/ca.crt:$(CA_DIR)/%.crt: openssl.conf $(CA_DIR)/%.req $(CA_DIR)/%.key
	$(call OPENSSL_X509) -days 10

$(CA_DIR)/%.crt: openssl.conf $(CA_DIR)/%.req $(CA_DIR)/ca.key | \
	$(CA_DIR)/.ca/newcerts $(CA_DIR)/.ca/index.txt $(CA_DIR)/.ca/serial
	$(call OPENSSL_CA) -days 10

$(CA_DIR)/ca.req:	CA_REQ=ca_cert
$(CA_DIR)/%.req: openssl.conf $(CA_DIR)/%.key | $(CA_DIR)
	$(OPENSSL_REQ) 

$(CA_DIR)/%.key: | $(CA_DIR)
	$(OPENSSL) genrsa -out $@ 2048

$(CA_DIR)/%.pem: $(CA_DIR)/%.crt $(CA_DIR)/%.key
	@rm -f $@
	$(OPENSSL) x509 -text -in $(filter %.crt,$^) -out $@
	cat $(filter %.key,$^) >> $@

.SECONDARY:

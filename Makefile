MODULE     := github.com/pqsec/sshlogin
PAM_SO     := pam_sshlogin.so
RESPONSE   := sshlogin-response
PAM_LIBDIR ?= /usr/lib64/security
BIN_DIR    ?= /usr/local/bin
CONTAINER_ENGINE ?= $(shell which podman 2>/dev/null || which docker 2>/dev/null)
IMAGE_NAME ?= sshlogin-test

.PHONY: all build build-pam build-response test clean install container-build container-shell test-container

all: build

build: build-pam build-response

build-pam: $(PAM_SO)

build-response: $(RESPONSE)

$(PAM_SO):
	go build -buildmode=c-shared -o $@ ./pam/

$(RESPONSE):
	go build -o $@ ./cmd/sshlogin-response/

test:
	go test -race -count=1 ./...

install: build
	install -d $(DESTDIR)$(PAM_LIBDIR)
	install -m 755 $(PAM_SO) $(DESTDIR)$(PAM_LIBDIR)/
	install -d $(DESTDIR)$(BIN_DIR)
	install -m 755 $(RESPONSE) $(DESTDIR)$(BIN_DIR)/

clean:
	rm -f $(PAM_SO) $(PAM_SO:.so=.h) $(RESPONSE)

container-build:
	$(CONTAINER_ENGINE) build -t $(IMAGE_NAME) -f Dockerfile .

container-shell: container-build
	$(CONTAINER_ENGINE) run --rm -it $(IMAGE_NAME)

test-container: container-shell

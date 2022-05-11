.DEFAULT_GOAL := default

platform := $(shell uname)

GOFMT_FILES?=$$(find ./ -name '*.go' | grep -v vendor)
DOCKER_IMG ?= form3tech/vault-plugin-secrets-grafanacloud)

default: build test

build: errcheck vet
	@find ./cmd/* -maxdepth 1 -type d -exec go install "{}" \;

install-lint:
	@go get -u golang.org/x/lint/golint

test:
	@echo "executing tests..."
	@go test -v ./...

vet:
	@echo "go vet ."
	@go vet $$(go list ./... | grep -v vendor/) ; if [ $$? -eq 1 ]; then \
		echo ""; \
		echo "Vet found suspicious constructs. Please check the reported constructs"; \
		echo "and fix them if necessary before submitting the code for review."; \
		exit 1; \
	fi

goimports:
	goimports -w $(GOFMT_FILES)

errcheck:
	@sh -c "'$(CURDIR)/scripts/errcheck.sh'"

vendor-status:
	@govendor status

docker-compose:
	@sh -c "'$(CURDIR)/setup-local.sh'"

install-vault:
	@wget https://releases.hashicorp.com/vault/1.0.3/vault_1.0.3_darwin_amd64.zip
	@unzip vault_1.0.3_darwin_amd64.zip
	@mv vault /usr/local/bin
	@rm vault_1.0.3_darwin_amd64.zip

generate:
	@go install github.com/golang/mock/mockgen@latest
	@go generate ./...

lint:
	@echo "go lint ."
	@golint $$(go list ./... | grep -v vendor/) ; if [ $$? -eq 1 ]; then \
		echo ""; \
		echo "Lint found errors in the source code. Please check the reported errors"; \
		echo "and fix them if necessary before submitting the code for review."; \
		exit 1; \
	fi


.PHONY: build test vet goimports errcheck lint vendor-status default docker-compose generate

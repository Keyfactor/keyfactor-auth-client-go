PROVIDER_DIR := $(PWD)
TEST?=$$(go list ./... | grep -v 'vendor')
HOSTNAME=keyfactor.com
GOFMT_FILES  := $$(find $(PROVIDER_DIR) -name '*.go' |grep -v vendor)
NAMESPACE=keyfactor
WEBSITE_REPO=https://github.com/Keyfactor/keyfactor-auth-client
NAME=keyfactor-auth-client
BINARY=${NAME}
VERSION := $(GITHUB_REF_NAME)
ifeq ($(VERSION),)
	VERSION := v1.0.0
endif
OS_ARCH := $(shell go env GOOS)_$(shell go env GOARCH)
BASEDIR := ${HOME}/go/bin
INSTALLDIR := ${BASEDIR}
MARKDOWN_FILE := README.md
TEMP_TOC_FILE := temp_toc.md



default: build

build: fmt
	go install

release:
	GOOS=darwin GOARCH=amd64 go build -o ./bin/${BINARY}_${VERSION}_darwin_amd64 -ldflags "-X 'keyfactor_auth_client/pkg.Version=${VERSION}' -X 'keyfactor_auth_client/pkg.BuildTime=$$(date)' -X 'keyfactor_auth_client/pkg.CommitHash=$$(git rev-parse HEAD)'"
	GOOS=freebsd GOARCH=386 go build -o ./bin/${BINARY}_${VERSION}_freebsd_386 -ldflags "-X 'keyfactor_auth_client/pkg.Version=${VERSION}' -X 'keyfactor_auth_client/pkg.BuildTime=$$(date)' -X 'keyfactor_auth_client/pkg.CommitHash=$$(git rev-parse HEAD)'"
	GOOS=freebsd GOARCH=amd64 go build -o ./bin/${BINARY}_${VERSION}_freebsd_amd64 -ldflags "-X 'keyfactor_auth_client/pkg.Version=${VERSION}' -X 'keyfactor_auth_client/pkg.BuildTime=$(date)' -X 'keyfactor_auth_client/pkg.CommitHash=$(git rev-parse HEAD)'"
	GOOS=freebsd GOARCH=arm go build -o ./bin/${BINARY}_${VERSION}_freebsd_arm -ldflags "-X 'keyfactor_auth_client/pkg.Version=${VERSION}' -X 'keyfactor_auth_client/pkg.BuildTime=$$(date)' -X 'keyfactor_auth_client/pkg.CommitHash=$$(git rev-parse HEAD)'"
	GOOS=linux GOARCH=386 go build -o ./bin/${BINARY}_${VERSION}_linux_386 -ldflags "-X 'keyfactor_auth_client/pkg.Version=${VERSION}' -X 'keyfactor_auth_client/pkg.BuildTime=$$(date)' -X 'keyfactor_auth_client/pkg.CommitHash=$$(git rev-parse HEAD)'"
	GOOS=linux GOARCH=amd64 go build -o ./bin/${BINARY}_${VERSION}_linux_amd64 -ldflags "-X 'keyfactor_auth_client/pkg.Version=${VERSION}' -X 'keyfactor_auth_client/pkg.BuildTime=$$(date)' -X 'keyfactor_auth_client/pkg.CommitHash=$$(git rev-parse HEAD)'"
	GOOS=linux GOARCH=arm go build -o ./bin/${BINARY}_${VERSION}_linux_arm -ldflags "-X 'keyfactor_auth_client/pkg.Version=${VERSION}' -X 'keyfactor_auth_client/pkg.BuildTime=$$(date)' -X 'keyfactor_auth_client/pkg.CommitHash=$$(git rev-parse HEAD)'"
	GOOS=openbsd GOARCH=386 go build -o ./bin/${BINARY}_${VERSION}_openbsd_386 -ldflags "-X 'keyfactor_auth_client/pkg.Version=${VERSION}' -X 'keyfactor_auth_client/pkg.BuildTime=$$(date)' -X 'keyfactor_auth_client/pkg.CommitHash=$$(git rev-parse HEAD)'"
	GOOS=openbsd GOARCH=amd64 go build -o ./bin/${BINARY}_${VERSION}_openbsd_amd64 -ldflags "-X 'keyfactor_auth_client/pkg.Version=${VERSION}' -X 'keyfactor_auth_client/pkg.BuildTime=$$(date)' -X 'keyfactor_auth_client/pkg.CommitHash=$$(git rev-parse HEAD)'"
	GOOS=solaris GOARCH=amd64 go build -o ./bin/${BINARY}_${VERSION}_solaris_amd64 -ldflags "-X 'keyfactor_auth_client/pkg.Version=${VERSION}' -X 'keyfactor_auth_client/pkg.BuildTime=$$(date)' -X 'keyfactor_auth_client/pkg.CommitHash=$$(git rev-parse HEAD)'"
	GOOS=windows GOARCH=386 go build -o ./bin/${BINARY}_${VERSION}_windows_386 -ldflags "-X 'keyfactor_auth_client/pkg.Version=${VERSION}' -X 'keyfactor_auth_client/pkg.BuildTime=$$(date)' -X 'keyfactor_auth_client/pkg.CommitHash=$$(git rev-parse HEAD)'"
	GOOS=windows GOARCH=amd64 go build -o ./bin/${BINARY}_${VERSION}_windows_amd64 -ldflags "-X 'keyfactor_auth_client/pkg.Version=${VERSION}' -X 'keyfactor_auth_client/pkg.BuildTime=$$(date)' -X 'keyfactor_auth_client/pkg.CommitHash=$$(git rev-parse HEAD)'"

install: fmt
	go build -o ${BINARY}
	rm -rf ${INSTALLDIR}/${BINARY}
	mkdir -p ${INSTALLDIR}
	chmod oug+x ${BINARY}
	cp ${BINARY} ${INSTALLDIR}
	mkdir -p ${HOME}/.local/bin || true
	mv ${BINARY} ${HOME}/.local/bin/${BINARY}

vendor:
	go mod vendor

version:
	@echo ${VERSION}

setversion:
	sed -i '' -e 's/VERSION = ".*"/VERSION = "$(VERSION)"/' pkg/version/version.go

test:
	go test -i $(TEST) || exit 1
	echo $(TEST) | xargs -t -n4 go test $(TESTARGS) -timeout=30s -parallel=4

fmt:
	gofmt -w $(GOFMT_FILES)

prerelease: fmt setversion
	git tag -d $(VERSION) || true
	git push origin :$(VERSION) || true
	git tag $(VERSION)
	git push origin $(VERSION)

check_toc:
	@grep -q 'TOC_START' $(MARKDOWN_FILE) && echo "TOC already exists." || (echo "TOC not found. Generating..." && $(MAKE) generate_toc)

generate_toc:
	# check if markdown-toc is installed and if not install it
	@command -v markdown-toc >/dev/null 2>&1 || (echo "markdown-toc is not installed. Installing..." && npm install -g markdown-toc)
	markdown-toc -i $(MARKDOWN_FILE) --skip 'Table of Contents'


.PHONY: build prerelease release install test fmt vendor version setversion
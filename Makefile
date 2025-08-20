pwd=$(shell pwd)

default: build

.PHONY: fmt
fmt:
	go fmt ./...

.PHONY: vet
vet:
	go vet ./...

.PHONY: lint
lint:
	golangci-lint run -v --fix ./...

.PHONY: clean
clean:
	rm -f cover.out cover.html $(NAME)
	rm -rf cover/

.PHONY: build
build: clean
	go build -o ./bin/scim ./cmd/scim

.PHONY: test
test: clean
	-$(MAKE) extract-version
	rm -rf cover cover.* junit.xml
	mkdir -p cover/unit cover/tenant-manager
	go clean -testcache

	# Run unit tests with coverage
	env TEST_ENV=make gotestsum --format testname --junitfile junit.xml \
		-- -count=1 -covermode=atomic -cover \
		./cmd/... ./pkg/... ./internal/... \
		-args -test.gocoverdir=$(pwd)/cover/unit

extract-version:
	echo \{\"version\": \"$(shell tail -c +2 VERSION)\"\} > build_version.json

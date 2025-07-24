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

.PHONY: test
test: clean
	mkdir -p cover/integration cover/unit
	go clean -testcache

	# unit tests
	go test -count=1 -race -cover ./... -args -test.gocoverdir="${PWD}/cover/unit"

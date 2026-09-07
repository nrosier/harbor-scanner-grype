.PHONY: test vet build lint-chart docker

test: ## run the Go test suite
	go test ./...

vet:
	go vet ./...

build:
	CGO_ENABLED=0 go build -o bin/adapter ./cmd/adapter

lint-chart:
	helm lint charts/harbor-scanner-grype

docker:
	docker build -t harbor-scanner-grype:dev .

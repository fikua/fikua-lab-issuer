.PHONY: run build test fmt vet

run:
	go run ./cmd/issuer

build:
	go build -trimpath -ldflags="-s -w" -o bin/issuer ./cmd/issuer

test:
	go test ./...

fmt:
	gofmt -l .

vet:
	go vet ./...

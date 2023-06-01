export PATH := $(GOPATH)/bin:$(PATH)
export GO111MODULE=on
LDFLAGS := -s -w

all: fmt build

build: server client

# compile assets into binary file
file:
	rm -rf ./assets/server/static/*
	rm -rf ./assets/client/static/*
	cp -rf ./web/server/dist/* ./assets/server/static
	cp -rf ./web/client/dist/* ./assets/client/static

fmt:
	go fmt ./...

fmt-more:
	gofumpt -l -w .

vet:
	go vet ./...

server:
	env CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/server ./cmd/server

client:
	env CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/client ./cmd/client

test: gotest

gotest:
	go test -v --cover ./assets/...
	go test -v --cover ./cmd/...
	go test -v --cover ./client/...
	go test -v --cover ./server/...
	go test -v --cover ./pkg/...

e2e:
	./hack/run-e2e.sh

e2e-trace:
	DEBUG=true LOG_LEVEL=trace ./hack/run-e2e.sh

alltest: vet gotest e2e
	
clean:
	rm -f ./bin/client
	rm -f ./bin/server

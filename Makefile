# vpn.io — convenience targets. Run `make help` for the menu.

# --- knobs you may want to override on the command line ----------------------
PUSH_ROUTES ?= 0.0.0.0/0
PUSH_DNS    ?= 1.1.1.1,9.9.9.9
SUBNET      ?= 10.8.0.0/24
GATEWAY     ?= 10.8.0.1
SERVER      ?= 127.0.0.1:8443
SERVER_NAME ?= localhost
CLIENT_NAME ?= alice
CA_HOSTS    ?= localhost,127.0.0.1

BIN := bin
GO  := go

.PHONY: help build test vet fmt lint clean clean-ca \
        ca-init ca-server ca-client \
        run-server run-client \
        cross

help:
	@echo "Targets:"
	@echo "  build           — build vpn-ca / vpn-server / vpn-client into ./$(BIN)/"
	@echo "  test            — go test -race ./..."
	@echo "  vet             — go vet ./..."
	@echo "  lint            — golangci-lint run ./... (needs golangci-lint v2)"
	@echo "  fmt             — gofmt -w ."
	@echo "  clean           — remove ./$(BIN)/ (keeps ca-data/)"
	@echo "  clean-ca        — remove ./ca-data/ (CA key + all certs; irreversible)"
	@echo "  cross           — cross-compile for linux/amd64 and windows/amd64"
	@echo
	@echo "  ca-init         — make a fresh CA in ./ca-data/"
	@echo "  ca-server       — issue server cert (CA_HOSTS=$(CA_HOSTS))"
	@echo "  ca-client       — issue client cert (CLIENT_NAME=$(CLIENT_NAME))"
	@echo
	@echo "  run-server      — sudo ./bin/vpn-server with sensible defaults"
	@echo "                    (PUSH_ROUTES=$(PUSH_ROUTES) PUSH_DNS=$(PUSH_DNS))"
	@echo "  run-client      — sudo ./bin/vpn-client against \$$SERVER ($(SERVER))"

build: $(BIN)/vpn-ca $(BIN)/vpn-server $(BIN)/vpn-client

$(BIN)/vpn-ca: $(shell find cmd/vpn-ca internal/ca -name '*.go' 2>/dev/null)
	@mkdir -p $(BIN)
	$(GO) build -o $@ ./cmd/vpn-ca

$(BIN)/vpn-server: $(shell find cmd/vpn-server internal -name '*.go' 2>/dev/null)
	@mkdir -p $(BIN)
	$(GO) build -o $@ ./cmd/vpn-server

$(BIN)/vpn-client: $(shell find cmd/vpn-client internal -name '*.go' 2>/dev/null)
	@mkdir -p $(BIN)
	$(GO) build -o $@ ./cmd/vpn-client

test:
	$(GO) test -race ./...

vet:
	$(GO) vet ./...

lint:
	golangci-lint run ./...

fmt:
	gofmt -w .

# clean removes only build output. It must never touch ca-data/: a single
# habitual `make clean` on the CA host used to destroy the CA private key and
# every issued cert — an irreversible "revoke-by-loss" of the whole fleet.
clean:
	rm -rf $(BIN)

# clean-ca is the explicit, opt-in way to wipe the CA. Not folded into clean.
clean-ca:
	rm -rf ca-data

cross:
	@echo "* linux/amd64"
	GOOS=linux  GOARCH=amd64 $(GO) build -o $(BIN)/linux-amd64/  ./cmd/vpn-ca ./cmd/vpn-server ./cmd/vpn-client
	@echo "* windows/amd64"
	GOOS=windows GOARCH=amd64 $(GO) build -o $(BIN)/windows-amd64/ ./cmd/vpn-ca ./cmd/vpn-server ./cmd/vpn-client

# --- CA convenience ----------------------------------------------------------

ca-init: $(BIN)/vpn-ca
	./$(BIN)/vpn-ca init

ca-server: $(BIN)/vpn-ca
	./$(BIN)/vpn-ca issue-server -hosts $(CA_HOSTS)

ca-client: $(BIN)/vpn-ca
	./$(BIN)/vpn-ca issue-client -name $(CLIENT_NAME)

# --- run --------------------------------------------------------------------

run-server: $(BIN)/vpn-server
	sudo ./$(BIN)/vpn-server \
	  -ca   ca-data/ca.crt \
	  -cert ca-data/server/server.crt \
	  -key  ca-data/server/server.key \
	  -subnet $(SUBNET) -gateway $(GATEWAY) \
	  -push-routes $(PUSH_ROUTES) \
	  -push-dns    $(PUSH_DNS) \
	  -log-level debug

run-client: $(BIN)/vpn-client
	sudo ./$(BIN)/vpn-client \
	  -server $(SERVER) -server-name $(SERVER_NAME) \
	  -ca   ca-data/ca.crt \
	  -cert ca-data/clients/$(CLIENT_NAME).crt \
	  -key  ca-data/clients/$(CLIENT_NAME).key \
	  -log-level debug

.PHONY: test cover lint bench yaegi-check e2e check

test:
	go test -race -count=1 ./...

cover:
	go test -count=1 -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -1

lint:
	@fmt_out="$$(gofmt -l .)"; \
	if [ -n "$$fmt_out" ]; then echo "gofmt: files not formatted:"; echo "$$fmt_out"; exit 1; fi
	go vet ./...
	golangci-lint run ./...
	fieldalignment ./...
	gosec -quiet ./...
	govulncheck ./...

bench:
	go test -run '^$$' -bench . -benchmem ./...

# Loads the plugin under Yaegi exactly as Traefik and the Plugin Catalog do.
yaegi-check:
	cd tools/yaegi-check && GOWORK=off go run . $(CURDIR)

# Runs the plugin in a real Traefik container; needs docker.
e2e:
	cd integration && go test -tags e2e -count=1 -v ./...

check: lint test yaegi-check e2e

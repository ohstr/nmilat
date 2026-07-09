set shell := ["bash", "-uc"]

# List all available recipes
default:
    @just --list --unsorted

# Compile-check every package (this is a library — there's no binary to build)
build:
    go build ./...

# Run the full test suite
test:
    go test ./...

# Vet all packages
vet:
    go vet ./...

# Tidy go.mod / go.sum
tidy:
    go mod tidy

# Run build, vet, and test together (local pre-push / pre-tag check)
check: build vet test

.PHONY: dev-build-up
dev-build-up: ## build for docker, build docker image and run docker-compose
	@env GOOS="linux" GOARCH=amd64 go build -o ./bin main.go
	@docker build -t auth1:local -f build/docker/Dockerfile .
	@docker-compose -f deployments/docker-compose/docker-compose.yml -p auth1 up -d

.PHONY: dev-build-down
dev-build-down: ## docker-compose down
	@docker-compose -f deployments/docker-compose/docker-compose.yml -p auth1 down

.PHONY: gen-mocks
gen-mocks: ## gen mocks for interfaces from pkg/service
	@mockery -dir pkg/service -all -output ./pkg/mocks

.PHONY: down
down: ## stops containers
	@docker-compose down

.PHONY: up
up: ## pull, builds and runs service and all deps
	@docker-compose pull && docker-compose up --build -d

.PHONY: upfast
upfast: ## pull, builds and runs service and all deps
	@docker-compose up -d

.PHONY: test
test: ## run go test
	@go test ./...

.PHONY: test-cover
test-cover: ## run go test with coverage
	@go test ./... -coverprofile=coverage.out -covermode=atomic

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

.DEFAULT_GOAL := help
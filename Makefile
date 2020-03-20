.PHONY: gen-mocks
gen-mocks: ## gen mocks for interfaces from pkg/service
	@ mockery -dir pkg/service -all -output ./pkg/mocks

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
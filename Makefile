.PHONY: up
up: ## pull, builds and runs service and all deps
	@docker-compose pull && docker-compose up --build

.PHONY: upfast
upfast: ## pull, builds and runs service and all deps
	@docker-compose up

.PHONY: down
down: ## stops containers
	@docker-compose down


.PHONY: up
up: ## pull, builds and runs service and all deps
	@docker-compose pull && docker-compose up --build -d

.PHONY: upfast
upfast: ## pull, builds and runs service and all deps
	@docker-compose up -d

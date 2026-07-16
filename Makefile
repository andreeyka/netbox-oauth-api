# Development shortcuts. See CONTRIBUTING.md for the full workflow.

# NetBox image tag for the integration stack (v4.0 … v4.4).
NETBOX_IMAGE_TAG ?= v4.4
COMPOSE = docker compose -f docker/docker-compose.yml

.PHONY: help lint format test build clean compose-up compose-logs compose-down e2e integration integration-all

help:
	@echo "lint             - ruff check + format check"
	@echo "format           - autoformat and autofix with ruff"
	@echo "test             - unit tests (no docker required)"
	@echo "build            - build sdist+wheel and validate metadata"
	@echo "compose-up       - start NetBox ($(NETBOX_IMAGE_TAG)) + Keycloak stack"
	@echo "e2e              - run integration tests against the running stack"
	@echo "compose-down     - stop the stack and remove volumes"
	@echo "integration      - compose-up + e2e + compose-down for NETBOX_IMAGE_TAG"
	@echo "integration-all  - run 'integration' for every supported NetBox version"

lint:
	ruff check .
	ruff format --check .

format:
	ruff format .
	ruff check --fix .

test:
	pytest

build:
	python -m build
	twine check dist/*

clean:
	rm -rf build dist *.egg-info .pytest_cache .coverage htmlcov

compose-up:
	NETBOX_IMAGE_TAG=$(NETBOX_IMAGE_TAG) $(COMPOSE) up -d --build --wait --wait-timeout 900

compose-logs:
	$(COMPOSE) logs --tail=100

compose-down:
	$(COMPOSE) down -v --remove-orphans

e2e:
	pytest integration_tests

integration: compose-up
	pytest integration_tests; status=$$?; $(COMPOSE) down -v --remove-orphans; exit $$status

integration-all:
	@for tag in v4.0 v4.1 v4.2 v4.3 v4.4; do \
		echo "=== NetBox $$tag ==="; \
		$(MAKE) integration NETBOX_IMAGE_TAG=$$tag || exit 1; \
	done

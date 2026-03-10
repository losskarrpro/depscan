.PHONY: help install dev test lint format clean run build docker-build docker-run

help:
	@echo "Available commands:"
	@echo "  install     Install production dependencies"
	@echo "  dev         Install development dependencies"
	@echo "  test        Run tests with pytest"
	@echo "  lint        Run linter (ruff)"
	@echo "  format      Format code (black)"
	@echo "  clean       Clean temporary files"
	@echo "  run         Run the CLI tool"
	@echo "  build       Build package"
	@echo "  docker-build Build Docker image"
	@echo "  docker-run   Run depscan in Docker"

install:
	pip install -e .

dev:
	pip install -e ".[dev]"

test:
	pytest -v --cov=scanner --cov-report=term-missing

lint:
	ruff check scanner tests

format:
	black scanner tests

clean:
	rm -rf build dist *.egg-info .coverage .pytest_cache
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete

run:
	python -m scanner.cli

build:
	python -m build

docker-build:
	docker build -t depscan .

docker-run:
	docker run --rm -v $(PWD):/app depscan
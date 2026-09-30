.PHONY: install test lint eval demo api mcp docker

install:
	pip install -e ".[dev]"

test:
	pytest --cov=opswatch --cov-report=term-missing

lint:
	ruff check src tests

eval:
	opswatch seed && opswatch train && opswatch eval --gate

demo:
	opswatch demo

api:
	opswatch serve-api

mcp:
	opswatch serve-mcp

docker:
	docker build -t opswatch . && docker run --rm -e OPSWATCH_API_KEY=dev-key -p 8000:8000 opswatch

.PHONY: clean test lint format install run init-tasks verify-beads

clean:
	rm -f .coverage
	rm -rf .pytest_cache src/__pycache__ src/dataset/__pycache__ tests/__pycache__ tests/unit/__pycache__

install:
	pip install -r requirements.txt
	pip install beads-task

init-tasks:
	bd init

test:
	pytest tests/unit --cov=src --cov-report=term-missing --cov-fail-under=70

lint:
	flake8 src tests --max-line-length=89
	isort src tests --check-only
	mypy src tests
	black src tests --check

format:
	isort src tests
	black src tests

run:
	python -m src.app

verify-beads:
	bd doctor --check=conventions

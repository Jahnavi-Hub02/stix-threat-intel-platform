.PHONY: install test run clean lint format

install:
	pip install -r requirements.txt

test:
	pytest

run:
	uvicorn app.api.main:app --reload --port 8000

clean:
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	rm -rf .pytest_cache .coverage

lint:
	flake8 app/ tests/

format:
	black app/ tests/

docker-build:
	docker build -t stix-threat-intel .

docker-run:
	docker-compose up
demo:
	python -m sentinel.cli gen && python -m sentinel.cli train && python -m sentinel.cli triage && python -m sentinel.cli list
test:
	ruff check . && python -m pytest -q
up:
	docker compose up -d --build

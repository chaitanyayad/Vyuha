# VYUHA — common tasks.
#
# On Windows without make, every target has a one-line equivalent in the
# README and in vyuha.ps1.

PY ?= .venv/Scripts/python.exe
ifeq ($(OS),)
PY = .venv/bin/python
endif

export PYTHONPATH := .

.PHONY: help venv dev test benchmark demo attack benign verify reset clean

help:
	@echo "  make venv       create .venv and install requirements"
	@echo "  make dev        run the gateway + dashboard on :8000"
	@echo "  make test       red-team suite, benign suite, ring and ledger tests"
	@echo "  make benchmark  regenerate results.json"
	@echo "  make demo       reset, benchmark, then serve the dashboard"
	@echo "  make attack     run attack A04 in the terminal (SCENARIO=A06 to pick)"
	@echo "  make verify     re-walk the ledger hash chain"
	@echo "  make reset      wipe vyuha.db and reseed"

venv:
	python -m venv .venv
	$(PY) -m pip install --upgrade pip
	$(PY) -m pip install -r requirements.txt

dev:
	$(PY) -m uvicorn gateway.api:app --host 127.0.0.1 --port 8000 --reload

test:
	$(PY) -m pytest tests -q

benchmark:
	$(PY) -m redteam.benchmark

SCENARIO ?= A04
attack:
	$(PY) -m redteam.cli $(SCENARIO)

benign:
	$(PY) -m redteam.cli B01

verify:
	$(PY) -m redteam.cli --verify

reset:
	$(PY) -m redteam.cli --reset

demo: reset benchmark
	@echo ""
	@echo "  Dashboard: http://127.0.0.1:8000"
	@echo ""
	$(PY) -m uvicorn gateway.api:app --host 127.0.0.1 --port 8000

clean:
	rm -rf __pycache__ */__pycache__ .pytest_cache vyuha.db results.json

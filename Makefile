.PHONY: help test test-rust test-python python-build clean

VENV := .venv-test
PYTHON := python3
PIP := $(VENV)/bin/pip
PYTEST := $(VENV)/bin/pytest
MATURIN := $(VENV)/bin/maturin

help:
	@echo "Targets:"
	@echo "  test         Run all tests (Rust + Python bindings)"
	@echo "  test-rust    Run cargo tests"
	@echo "  test-python  Build the Python extension and run binding smoke tests"
	@echo "  python-build Build the Python extension into the test venv only"
	@echo "  clean        Remove the test virtualenv"

test: test-rust test-python

test-rust:
	cargo test

$(VENV):
	$(PYTHON) -m venv $(VENV)
	$(PIP) install --upgrade pip
	$(PIP) install maturin pytest

python-build: $(VENV)
	. $(VENV)/bin/activate && $(MATURIN) develop --features python

test-python: python-build
	. $(VENV)/bin/activate && $(PYTEST) -v tests/python_bindings/

clean:
	rm -rf $(VENV)

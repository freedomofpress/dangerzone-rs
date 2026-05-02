"""Pytest configuration for the Python-binding smoke tests.

Importing dangerzone_rs requires the extension module to be built and
installed in the active environment (e.g. via `maturin develop --features
python`). If the import fails, fail loudly with an actionable hint.
"""

import pytest


def pytest_configure(config):
    try:
        import dangerzone_rs  # noqa: F401
    except ImportError as e:
        pytest.exit(
            f"Could not import dangerzone_rs: {e}\n"
            "Build the extension first, e.g.:\n"
            "    make test-python\n"
            "or manually:\n"
            "    pip install maturin pytest\n"
            "    maturin develop --features python\n"
            "    pytest tests/python_bindings/",
            returncode=2,
        )

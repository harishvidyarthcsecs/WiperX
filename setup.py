# Configuration now lives in pyproject.toml (PEP 621). This shim keeps
# `python setup.py ...` and older tooling working.
from setuptools import setup

setup()

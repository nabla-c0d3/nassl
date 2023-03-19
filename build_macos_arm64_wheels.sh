#!/bin/bash

# Python 3.9+ arm64 is required
python -m pip install "cibuildwheel<2.13"

export CIBW_ARCHS_MACOS="arm64"
export CIBW_BEFORE_ALL='python -m pip install invoke && invoke build.deps'
export CIBW_BEFORE_BUILD='python -m pip install invoke && invoke build.nassl'
export CIBW_BUILD='cp39-* cp310-* cp311-*'
export CIBW_TEST_COMMAND='python -m pytest {project}/tests'
export CIBW_TEST_REQUIRES="pytest"

python -m cibuildwheel --output-dir wheelhouse --platform macos

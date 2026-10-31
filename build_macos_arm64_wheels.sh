#!/bin/bash

python -m pip install "cibuildwheel>=4.3.1,<4.4"

export CIBW_ARCHS_MACOS="arm64"
export CIBW_BEFORE_ALL='python -m pip install invoke && invoke build.deps'
export CIBW_BEFORE_BUILD='python -m pip install invoke setuptools && invoke build.nassl'
export CIBW_BUILD='cp311-* cp312-* cp313-* cp314-* cp315-*'
export CIBW_TEST_COMMAND='python -m pytest {project}/tests'
export CIBW_TEST_REQUIRES="pytest"

python -m cibuildwheel --output-dir wheelhouse --platform macos

#!/bin/sh
set -e

# This is needed to build OpenSSL 4, which is unable to find some perl dependencies it needs in order to be built
if [ -f /etc/os-release ]; then
    . /etc/os-release
    if [ "$ID" = "alpine" ] || grep -q "musllinux" /etc/os-release 2>/dev/null; then
        echo "Installing dependencies for musllinux..."
        apk add --no-cache perl perl-utils
    else
        echo "Installing dependencies for manylinux..."
        yum install -y perl-IPC-Cmd perl-Time-Piece
    fi
fi

python -m pip install setuptools invoke && invoke build.deps

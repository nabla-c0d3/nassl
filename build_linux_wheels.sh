#!/bin/bash
set -e -x

# docker run --rm -v D:\GitHub\nassl\:/io quay.io/pypa/manylinux1_i686 bash /io/build_linux_wheels.sh

# Compile wheels
for PYBIN in "cp27-cp27m" "cp34-cp34m" "cp35-cp35m" "cp36-cp36m"; do
    "/opt/python/${PYBIN}/bin/pip" install -r /io/requirements.txt
    "/opt/python/${PYBIN}/bin/pip" wheel /io/ -w wheelhouse/
done

# Bundle external shared libraries into the wheels
for whl in wheelhouse/nassl*.whl; do
    auditwheel repair "$whl" -w /io/wheelhouse/
done

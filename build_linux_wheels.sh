#!/bin/bash
set -e -x


cd /io

# First build non-Python dependencies (Zlib, OpenSSL) using Python 3.7
"/opt/python/cp37-cp37m/bin/pip" install pipenv
"/opt/python/cp37-cp37m/bin/pipenv" --python "/opt/python/cp37-cp37m/bin/python" install --dev
"/opt/python/cp37-cp37m/bin/pipenv" run invoke build.zlib
"/opt/python/cp37-cp37m/bin/pipenv" run invoke build.legacy-openssl
"/opt/python/cp37-cp37m/bin/pipenv" run invoke build.modern-openssl

# Now build the Python extension and wheel
for PYBIN in "cp37-cp37m" "cp38-cp38"; do
    "/opt/python/${PYBIN}/bin/python" setup.py clean --all
    "/opt/python/${PYBIN}/bin/python" setup.py build_ext -i

    # Compile wheels
    "/opt/python/${PYBIN}/bin/pip" wheel /io -w wheelhouse/
done


# Bundle external shared libraries into the wheels
for whl in wheelhouse/nassl*.whl; do
    auditwheel repair "$whl" -w /io/wheelhouse/
done

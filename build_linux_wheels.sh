#!/bin/bash
set -e -x

# Update perl as OpenSSL 1.1.x requires 5.10; there's probably a better/Docker way to do this
curl http://www.cpan.org/src/perl-5.10.1.tar.gz -o perl-5.10.1.tar.gz
tar -xzf perl-5.10.1.tar.gz
cd perl-5.10.1
./Configure -des -Dprefix=$HOME/localperl
make
make install
export PATH=$HOME/localperl/bin:$PATH


cd /io

# First build non-Python dependencies (Zlib, OpenSSL) using Python 3.6
"/opt/python/cp36-cp36m/bin/pip" install pipenv
"/opt/python/cp36-cp36m/bin/pipenv" --python "/opt/python/cp36-cp36m/bin/python" install --dev
"/opt/python/cp36-cp36m/bin/pipenv" run invoke build.zlib
"/opt/python/cp36-cp36m/bin/pipenv" run invoke build.legacy-openssl
"/opt/python/cp36-cp36m/bin/pipenv" run invoke build.modern-openssl

# Create a requirements file as we won't use pipenv after this point
"/opt/python/cp36-cp36m/bin/pipenv" lock -r --dev > requirements.txt

# Now build the Python extension and wheel
for PYBIN in "cp37-cp37m" "cp36-cp36m"; do
    "/opt/python/${PYBIN}/bin/python" setup.py clean --all
    "/opt/python/${PYBIN}/bin/python" setup.py build_ext -i
    "/opt/python/${PYBIN}/bin/pip" install -r requirements.txt

    # Compile wheels
    "/opt/python/${PYBIN}/bin/pip" wheel /io/ -w wheelhouse/
done


# Bundle external shared libraries into the wheels
for whl in wheelhouse/nassl*.whl; do
    auditwheel repair "$whl" -w /io/wheelhouse/
done

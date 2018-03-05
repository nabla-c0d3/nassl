#!/bin/bash
set -e -x

# Update perl as OpenSSL 1.1.x requires 5.10; there's probably a better/Docker way to do this
wget http://www.cpan.org/src/perl-5.10.1.tar.gz
tar -xzf perl-5.10.1.tar.gz
cd perl-5.10.1
./Configure -des -Dprefix=$HOME/localperl
make
make install
export PATH=$HOME/localperl/bin:$PATH

# Build Zlib, OpenSSL
cd ../io
"/opt/python/cp36-cp36m/bin/python" build_from_scratch.py
cd ..

# Compile wheels
for PYBIN in "cp27-cp27m" "cp34-cp34m" "cp35-cp35m" "cp36-cp36m"; do
    "/opt/python/${PYBIN}/bin/pip" install -r /io/requirements.txt
    "/opt/python/${PYBIN}/bin/pip" wheel /io/ -w wheelhouse/
done

# Bundle external shared libraries into the wheels
for whl in wheelhouse/nassl*.whl; do
    auditwheel repair "$whl" -w /io/wheelhouse/
done

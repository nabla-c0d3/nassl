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

# Build everything
cd ../io
"/opt/python/cp36-cp36m/bin/pip" install pipenv
"/opt/python/cp36-cp36m/bin/pipenv" --python "/opt/python/cp36-cp36m/bin/python" install --dev
"/opt/python/cp36-cp36m/bin/pipenv" run invoke -c build_tasks build-all
cd ..

# Compile wheels
"/opt/python/cp36-cp36m/bin/pip" wheel /io/ -w wheelhouse/


# Bundle external shared libraries into the wheels
for whl in wheelhouse/nassl*.whl; do
    auditwheel repair "$whl" -w /io/wheelhouse/
done

import subprocess
from sys import platform
from nassl import _nassl, _nassl_legacy
import pytest

can_only_run_on_linux_64 = pytest.mark.skipif(
    condition=platform not in ["linux", "linux2"], reason="The test suite it not being run on Linux"
)


class TestBuildConfig:
    @can_only_run_on_linux_64
    @pytest.mark.parametrize("nassl_module", [_nassl, _nassl_legacy])
    def test_internal_openssl_symbols_are_hidden(self, nassl_module):
        # Given the compiled _nassl module
        # When looking at the module's shared library's symbol table
        symbol_table = subprocess.run(["nm", "-gD", f"{nassl_module.__file__}"], capture_output=True).stdout

        # Then internal symbols from the statically linked OpenSSL libraries are not present, so that no
        # "symbol confusion" can occur when Python loads the system's OpenSSL libraries (which are incompatible with
        # nassl). See also https://github.com/nabla-c0d3/nassl/issues/95
        assert "RSA_verify" not in symbol_table.decode("ascii")

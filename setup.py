import copy
import sys
from pathlib import Path

from build_config import (
    OpenSSL_4_0_0_BuildConfig,
    OpenSsl_1_0_2_BuildConfig,
    OpenSsl_1_1_1_BuildConfig,
    ZlibBuildConfig,
    SupportedPlatformEnum,
    CURRENT_PLATFORM,
)
from nassl import __author__, __version__
from setuptools import setup, Extension, find_packages

SHOULD_BUILD_FOR_DEBUG = False


NASSL_SETUP = {
    "name": "nassl",
    "version": __version__,
    "packages": find_packages(exclude=["docs", "tests"]),
    "package_data": {"nassl": ["py.typed", "_nassl.pyi", "_nassl_legacy.pyi"]},
    "py_modules": [
        "nassl.__init__",
        "nassl.ssl_client",
        "nassl.ephemeral_key_info",
        "nassl.legacy_ssl_client",
        "nassl.ocsp_response",
        "nassl.cert_chain_verifier",
    ],
    "description": "Experimental OpenSSL wrapper for Python 3.10+ and SSLyze.",
    "author": __author__,
    "author_email": "nabla.c0d3@gmail.com",
    "url": "https://github.com/nabla-c0d3/nassl",
    "python_requires": ">=3.10",
    "classifiers": [
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Natural Language :: French",
        "License :: OSI Approved :: GNU Affero General Public License v3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Programming Language :: Python :: 3.14",
        "Topic :: System :: Networking",
        "Topic :: System :: Monitoring",
        "Topic :: System :: Networking :: Monitoring",
        "Topic :: Security",
    ],
    "keywords": "ssl tls scan security library",
}

# There are multiple native extensions:
#   * one wrapping OpenSSL 1.0.2
#   * one wrapping OpenSSL 1.1.1
#   * one wrapping OpenSSL 4.0.0
# First setup the common settings for all extensions
BASE_NASSL_EXT_SETUP = {
    "extra_compile_args": [],
    "extra_link_args": [],
    "sources": [
        "nassl/_nassl/nassl.c",
        "nassl/_nassl/nassl_SSL_CTX.c",
        "nassl/_nassl/nassl_SSL.c",
        "nassl/_nassl/nassl_errors.c",
        "nassl/_nassl/nassl_BIO.c",
        "nassl/_nassl/nassl_SSL_SESSION.c",
        "nassl/_nassl/openssl_utils.c",
        "nassl/_nassl/nassl_OCSP_RESPONSE.c",
        "nassl/_nassl/python_utils.c",
    ],
}

if CURRENT_PLATFORM in [
    SupportedPlatformEnum.WINDOWS_32,
    SupportedPlatformEnum.WINDOWS_64,
]:
    # Build using the Python that was used to run this script; will not work for cross-compiling
    PYTHON_LIBS_PATH = Path(sys.executable).parent / "libs"

    BASE_NASSL_EXT_SETUP.update(
        {
            "library_dirs": [str(PYTHON_LIBS_PATH)],
            "libraries": [
                "user32",
                "kernel32",
                "Gdi32",
                "Advapi32",
                "Ws2_32",
                "crypt32",
            ],
        }
    )
else:
    BASE_NASSL_EXT_SETUP["extra_compile_args"].append("-Wall")

    if CURRENT_PLATFORM in SupportedPlatformEnum.all_linux_platforms():
        # Hide internal OpenSSL symbols to avoid "symbol confusion" when Python loads the system's OpenSSL libraries
        # https://github.com/nabla-c0d3/nassl/issues/95
        BASE_NASSL_EXT_SETUP["extra_link_args"].append("-Wl,--exclude-libs=ALL")

    if CURRENT_PLATFORM == SupportedPlatformEnum.LINUX_64:
        # Explicitly disable executable stack on Linux 64 to address issues with Ubuntu on Windows
        # https://github.com/nabla-c0d3/nassl/issues/28
        BASE_NASSL_EXT_SETUP["extra_link_args"].append("-Wl,-z,noexecstack")

zlib_config = ZlibBuildConfig(CURRENT_PLATFORM)


# The configure the setup for 1.0.2
openssl_1_0_2_config = OpenSsl_1_0_2_BuildConfig(CURRENT_PLATFORM)

NASSL_OSSL_1_0_2_EXT_SETUP = copy.deepcopy(BASE_NASSL_EXT_SETUP)
NASSL_OSSL_1_0_2_EXT_SETUP["name"] = "nassl.openssl_1_0_2._nassl"
NASSL_OSSL_1_0_2_EXT_SETUP["define_macros"] = [("NASSL_OSSL_1_0_2", "1")]
NASSL_OSSL_1_0_2_EXT_SETUP.update(
    {
        "include_dirs": [str(openssl_1_0_2_config.include_path)],
        "extra_objects": [
            # The order matters on some flavors of Linux
            str(openssl_1_0_2_config.libssl_path),
            str(openssl_1_0_2_config.libcrypto_path),
            str(zlib_config.libz_path),
        ],
    }
)

# The configure the setup for 1.1.1
openssl_1_1_1_config = OpenSsl_1_1_1_BuildConfig(CURRENT_PLATFORM)

NASSL_OSSL_1_1_1_EXT_SETUP = copy.deepcopy(BASE_NASSL_EXT_SETUP)
NASSL_OSSL_1_1_1_EXT_SETUP["name"] = "nassl.openssl_1_1_1._nassl"
NASSL_OSSL_1_1_1_EXT_SETUP.update(
    {
        "include_dirs": [str(openssl_1_1_1_config.include_path)],
        "extra_objects": [
            # The order matters on some flavors of Linux
            str(openssl_1_1_1_config.libssl_path),
            str(openssl_1_1_1_config.libcrypto_path),
            str(zlib_config.libz_path),
        ],
    }
)

# The configure the setup for 4.0.0
openssl_4_0_0_config = OpenSSL_4_0_0_BuildConfig(CURRENT_PLATFORM)

NASSL_OSSL_4_0_0_EXT_SETUP = copy.deepcopy(BASE_NASSL_EXT_SETUP)
NASSL_OSSL_4_0_0_EXT_SETUP["name"] = "nassl.openssl_4_0_0._nassl"
NASSL_OSSL_4_0_0_EXT_SETUP["define_macros"] = [("NASSL_OSSL_4_0_0", "1")]
NASSL_OSSL_4_0_0_EXT_SETUP.update(
    {
        "include_dirs": [str(openssl_4_0_0_config.include_path)],
        "extra_objects": [
            # The order matters on some flavors of Linux
            str(openssl_4_0_0_config.libssl_path),
            str(openssl_4_0_0_config.libcrypto_path),
            str(zlib_config.libz_path),
        ],
    }
)


if CURRENT_PLATFORM in [
    SupportedPlatformEnum.WINDOWS_32,
    SupportedPlatformEnum.WINDOWS_64,
]:
    if SHOULD_BUILD_FOR_DEBUG:
        NASSL_OSSL_1_0_2_EXT_SETUP.update({"extra_compile_args": ["/Zi"], "extra_link_args": ["/DEBUG"]})
        NASSL_OSSL_1_1_1_EXT_SETUP.update({"extra_compile_args": ["/Zi"], "extra_link_args": ["/DEBUG"]})
        NASSL_OSSL_4_0_0_EXT_SETUP.update({"extra_compile_args": ["/Zi"], "extra_link_args": ["/DEBUG"]})
else:
    # Add arguments specific to Unix builds
    NASSL_OSSL_1_0_2_EXT_SETUP["include_dirs"].append(str(Path("nassl") / "_nassl"))
    NASSL_OSSL_1_1_1_EXT_SETUP["include_dirs"].append(str(Path("nassl") / "_nassl"))
    NASSL_OSSL_4_0_0_EXT_SETUP["include_dirs"].append(str(Path("nassl") / "_nassl"))


NASSL_SETUP.update(
    {
        "ext_modules": [
            Extension(**NASSL_OSSL_1_0_2_EXT_SETUP),
            Extension(**NASSL_OSSL_1_1_1_EXT_SETUP),
            Extension(**NASSL_OSSL_4_0_0_EXT_SETUP),
        ]
    }
)


if __name__ == "__main__":
    setup(**NASSL_SETUP)

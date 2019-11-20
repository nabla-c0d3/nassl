import sys
from pathlib import Path

from build_tasks import (
    ModernOpenSslBuildConfig,
    ZlibBuildConfig,
    LegacyOpenSslBuildConfig,
    SupportedPlatformEnum,
    CURRENT_PLATFORM,
)
from nassl import __author__, __version__
from setuptools import setup, Extension

SHOULD_BUILD_FOR_DEBUG = False


NASSL_SETUP = {
    "name": "nassl",
    "version": __version__,
    "package_dir": {"nassl": "nassl"},
    "py_modules": ["nassl.__init__", "nassl.ssl_client", "nassl.key_exchange_info", "nassl.legacy_ssl_client", "nassl.ocsp_response"],
    "description": "Experimental OpenSSL wrapper for Python 3.7+ and SSLyze.",
    "author": __author__,
    "author_email": "nabla.c0d3@gmail.com",
    "url": "https://github.com/nabla-c0d3/nassl",
    "python_requires": ">=3.7",
    "classifiers": [
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Natural Language :: French",
        "License :: OSI Approved :: GNU Affero General Public License v3",
        "Programming Language :: Python :: 3.7",
        "Topic :: System :: Networking",
        "Topic :: System :: Monitoring",
        "Topic :: System :: Networking :: Monitoring",
        "Topic :: Security",
    ],
    "keywords": "ssl tls scan security library",
}

# There are two native extensions: the "legacy" OpenSSL one and the "modern" OpenSSL one
BASE_NASSL_EXT_SETUP = {
    "extra_compile_args": [],
    "extra_link_args": [],
    "sources": [
        "nassl/_nassl/nassl.c",
        "nassl/_nassl/nassl_SSL_CTX.c",
        "nassl/_nassl/nassl_SSL.c",
        "nassl/_nassl/nassl_X509.c",
        "nassl/_nassl/nassl_errors.c",
        "nassl/_nassl/nassl_BIO.c",
        "nassl/_nassl/nassl_SSL_SESSION.c",
        "nassl/_nassl/openssl_utils.c",
        "nassl/_nassl/nassl_OCSP_RESPONSE.c",
        "nassl/_nassl/python_utils.c",
    ],
}

if CURRENT_PLATFORM in [SupportedPlatformEnum.WINDOWS_32, SupportedPlatformEnum.WINDOWS_64]:
    # Build using the Python that was used to run this script; will not work for cross-compiling
    PYTHON_LIBS_PATH = Path(sys.executable).parent / "libs"

    BASE_NASSL_EXT_SETUP.update(
        {
            "library_dirs": [str(PYTHON_LIBS_PATH)],
            "libraries": ["user32", "kernel32", "Gdi32", "Advapi32", "Ws2_32", "crypt32"],
        }
    )
else:
    BASE_NASSL_EXT_SETUP["extra_compile_args"].append("-Wall")

    if CURRENT_PLATFORM == SupportedPlatformEnum.LINUX_64:
        # Explicitly disable executable stack on Linux 64 to address issues with Ubuntu on Windows
        # https://github.com/nabla-c0d3/nassl/issues/28
        BASE_NASSL_EXT_SETUP["extra_link_args"].append("-Wl,-z,noexecstack")


legacy_openssl_config = LegacyOpenSslBuildConfig(CURRENT_PLATFORM)
modern_openssl_config = ModernOpenSslBuildConfig(CURRENT_PLATFORM)
zlib_config = ZlibBuildConfig(CURRENT_PLATFORM)

LEGACY_NASSL_EXT_SETUP = BASE_NASSL_EXT_SETUP.copy()
LEGACY_NASSL_EXT_SETUP["name"] = "nassl._nassl_legacy"
LEGACY_NASSL_EXT_SETUP["define_macros"] = [("LEGACY_OPENSSL", "1")]
LEGACY_NASSL_EXT_SETUP.update(
    {
        "include_dirs": [str(legacy_openssl_config.include_path)],
        "extra_objects": [
            # The order matters on some flavors of Linux
            str(legacy_openssl_config.libssl_path),
            str(legacy_openssl_config.libcrypto_path),
            str(zlib_config.libz_path),
        ],
    }
)

MODERN_NASSL_EXT_SETUP = BASE_NASSL_EXT_SETUP.copy()
MODERN_NASSL_EXT_SETUP["name"] = "nassl._nassl"
MODERN_NASSL_EXT_SETUP.update(
    {
        "include_dirs": [str(modern_openssl_config.include_path)],
        "extra_objects": [
            # The order matters on some flavors of Linux
            str(modern_openssl_config.libssl_path),
            str(modern_openssl_config.libcrypto_path),
            str(zlib_config.libz_path),
        ],
    }
)

if CURRENT_PLATFORM in [SupportedPlatformEnum.WINDOWS_32, SupportedPlatformEnum.WINDOWS_64]:
    if SHOULD_BUILD_FOR_DEBUG:
        LEGACY_NASSL_EXT_SETUP.update({"extra_compile_args": ["/Zi"], "extra_link_args": ["/DEBUG"]})
        MODERN_NASSL_EXT_SETUP.update({"extra_compile_args": ["/Zi"], "extra_link_args": ["/DEBUG"]})
else:
    # Add arguments specific to Unix builds
    LEGACY_NASSL_EXT_SETUP["include_dirs"].append(str(Path("nassl") / "_nassl"))
    MODERN_NASSL_EXT_SETUP["include_dirs"].append(str(Path("nassl") / "_nassl"))


NASSL_SETUP.update({"ext_modules": [Extension(**LEGACY_NASSL_EXT_SETUP), Extension(**MODERN_NASSL_EXT_SETUP)]})


if __name__ == "__main__":
    setup(**NASSL_SETUP)

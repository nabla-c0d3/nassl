import shutil
import tarfile
from abc import ABC, abstractmethod
from enum import Enum
from pathlib import Path
from tempfile import TemporaryFile
from platform import architecture, machine
from sys import platform
from typing import Optional, Any
from urllib.request import urlopen

# Monkeypatch for Python 3.11
# TODO: Remove after this is fixed: https://github.com/pyinvoke/invoke/issues/833
import inspect

if not hasattr(inspect, "getargspec"):
    inspect.getargspec = inspect.getfullargspec

try:
    from invoke import task, Context
except ImportError:
    # This will happen when doing pip install nassl in an environment that does not have invoke pre-installed
    # We still want this script to be usable directly by pip
    def task(*args, **kwargs):  # type: ignore
        # Return a function - anything will do
        return repr

    Context = Any


# Where we store the src packages of OpenSSL and Zlib
_DEPS_PATH = Path(__file__).parent.absolute() / "deps"


class SupportedPlatformEnum(Enum):
    """Platforms supported by nassl."""

    OSX_64 = 1
    LINUX_64 = 2
    LINUX_32 = 3
    WINDOWS_32 = 4
    WINDOWS_64 = 5
    OPENBSD_64 = 6
    OSX_ARM64 = 7
    LINUX_ARM64 = 8
    LINUX_ARM32 = 9


CURRENT_PLATFORM = None
if architecture()[0] == "64bit":
    if platform == "darwin":
        if machine() == "x86_64":
            CURRENT_PLATFORM = SupportedPlatformEnum.OSX_64
        else:
            CURRENT_PLATFORM = SupportedPlatformEnum.OSX_ARM64
    elif platform in ["linux", "linux2"]:
        if machine() == "aarch64":
            CURRENT_PLATFORM = SupportedPlatformEnum.LINUX_ARM64
        else:
            CURRENT_PLATFORM = SupportedPlatformEnum.LINUX_64
    elif platform == "win32":
        CURRENT_PLATFORM = SupportedPlatformEnum.WINDOWS_64
    elif platform == "openbsd5":
        CURRENT_PLATFORM = SupportedPlatformEnum.OPENBSD_64
elif architecture()[0] == "32bit":
    if platform in ["linux", "linux2"]:
        if machine() == "armv7l":
            CURRENT_PLATFORM = SupportedPlatformEnum.LINUX_ARM32
        else:
            CURRENT_PLATFORM = SupportedPlatformEnum.LINUX_32
    elif platform == "win32":
        CURRENT_PLATFORM = SupportedPlatformEnum.WINDOWS_32


class BuildConfig(ABC):
    """Base class we use to configure and build Zlib and OpenSSL."""

    def __init__(self, platform: SupportedPlatformEnum) -> None:
        self.platform = platform

    @property
    @abstractmethod
    def src_path(self) -> Path:
        """Where the src package is extracted to before trying to build it."""
        pass

    def clean(self) -> None:
        shutil.rmtree(self.src_path, ignore_errors=True)

    @property
    @abstractmethod
    def src_tar_gz_url(self) -> str:
        """Where to download src package from."""
        pass

    def fetch_source(self) -> None:
        """Download the tar archive that contains the source code for the library."""
        with TemporaryFile() as temp_file:
            # Download the source archive
            with urlopen(self.src_tar_gz_url) as src_tar_gz_response:
                temp_file.write(src_tar_gz_response.read())

            # Rewind the file
            temp_file.seek(0)

            # Extract the content of the archive
            tar_file = tarfile.open(fileobj=temp_file)
            tar_file.extractall(path=_DEPS_PATH)

    @abstractmethod
    def build(self, ctx: Context) -> None:
        pass

    @property
    @abstractmethod
    def include_path(self) -> Path:
        pass


class OpenSslBuildConfig(BuildConfig, ABC):
    @property
    @abstractmethod
    def _openssl_git_tag(self) -> str:
        pass

    @property
    def src_tar_gz_url(self) -> str:
        return f"https://github.com/openssl/openssl/archive/{self._openssl_git_tag}.tar.gz"

    @property
    def src_path(self) -> Path:
        return _DEPS_PATH / f"openssl-{self._openssl_git_tag}"

    @property
    @abstractmethod
    def libcrypto_path(self) -> Path:
        pass

    @property
    @abstractmethod
    def libssl_path(self) -> Path:
        pass

    @property
    @abstractmethod
    def exe_path(self) -> Path:
        pass

    def _get_build_target(self, should_build_for_debug: bool) -> str:
        if self.platform == SupportedPlatformEnum.WINDOWS_32:
            openssl_target = "VC-WIN32"
        elif self.platform == SupportedPlatformEnum.WINDOWS_64:
            openssl_target = "VC-WIN64A"
        elif self.platform == SupportedPlatformEnum.OSX_64:
            openssl_target = "darwin64-x86_64-cc"
        elif self.platform == SupportedPlatformEnum.OSX_ARM64:
            openssl_target = "arm64-x86_64-cc"
        elif self.platform == SupportedPlatformEnum.LINUX_64:
            openssl_target = "linux-x86_64"
        elif self.platform == SupportedPlatformEnum.LINUX_32:
            openssl_target = "linux-elf"
        elif self.platform == SupportedPlatformEnum.LINUX_ARM64:
            openssl_target = "linux-aarch64"
        elif self.platform == SupportedPlatformEnum.LINUX_ARM32:
            openssl_target = "linux-armv4"
        else:
            raise ValueError("Unknown platform")

        if should_build_for_debug:
            if self.platform not in [
                SupportedPlatformEnum.WINDOWS_32,
                SupportedPlatformEnum.WINDOWS_64,
            ]:
                raise ValueError("Debug builds only supported for Windows")
            else:
                openssl_target = f"debug-{openssl_target}"

        return openssl_target

    def build(
        self,
        ctx: Context,
        zlib_lib_path: Optional[Path] = None,
        zlib_include_path: Optional[Path] = None,
        should_build_for_debug: bool = False,
    ) -> None:
        if not zlib_lib_path or not zlib_include_path:
            raise ValueError("Missing argument")

        # Build OpenSSL
        openssl_target = self._get_build_target(should_build_for_debug)
        with ctx.cd(str(self.src_path)):
            self._run_configure_command(ctx, openssl_target, zlib_lib_path, zlib_include_path)
            self._run_build_steps(ctx)

    # To be defined in subclasses
    _OPENSSL_CONF_CMD: str = None

    def _run_configure_command(
        self, ctx: Context, openssl_target: str, zlib_lib_path: Path, zlib_include_path: Path
    ) -> None:
        if self.platform in [SupportedPlatformEnum.WINDOWS_32, SupportedPlatformEnum.WINDOWS_64]:
            extra_args = "-no-asm -DZLIB_WINAPI"  # *hate* zlib
            # On Windows OpenSSL wants the full path to the lib file
            final_zlib_path = zlib_lib_path
        else:
            extra_args = " -fPIC"
            # On Unix OpenSSL wants the path to the folder where the lib is
            final_zlib_path = zlib_lib_path.parent

        ctx.run(
            self._OPENSSL_CONF_CMD.format(
                target=openssl_target,
                zlib_lib_path=final_zlib_path,
                zlib_include_path=zlib_include_path,
                extra_args=extra_args,
            )
        )

    def _run_build_steps(self, ctx: Context) -> None:
        if self.platform in [SupportedPlatformEnum.WINDOWS_32, SupportedPlatformEnum.WINDOWS_64]:
            if self.platform == SupportedPlatformEnum.WINDOWS_32:
                ctx.run("ms\\do_ms")
            else:
                ctx.run("ms\\do_win64a.bat")

            ctx.run(
                "nmake -f ms\\nt.mak clean", warn=True
            )  # Does not work if tmp32 does not exist (fresh build)
            ctx.run("nmake -f ms\\nt.mak")

        else:
            ctx.run("make clean", warn=True)
            ctx.run("make")  # Only build the libs as it is faster - not available on Windows


class LegacyOpenSslBuildConfig(OpenSslBuildConfig):
    @property
    def _openssl_git_tag(self) -> str:
        return "OpenSSL_1_0_2e"

    _OPENSSL_CONF_CMD = (
        "perl Configure {target} zlib no-zlib-dynamic no-shared enable-rc5 enable-md2 enable-gost "
        "enable-cast enable-idea enable-ripemd enable-mdc2 --with-zlib-include={zlib_include_path} "
        "--with-zlib-lib={zlib_lib_path} {extra_args}"
    )

    @property
    def include_path(self) -> Path:
        if self.platform in [SupportedPlatformEnum.WINDOWS_32, SupportedPlatformEnum.WINDOWS_64]:
            return self.src_path / "inc32"
        else:
            return self.src_path / "include"

    @property
    def libcrypto_path(self) -> Path:
        if self.platform in [SupportedPlatformEnum.WINDOWS_32, SupportedPlatformEnum.WINDOWS_64]:
            return self.src_path / "out32" / "libeay32.lib"
        else:
            return self.src_path / "libcrypto.a"

    @property
    def libssl_path(self) -> Path:
        if self.platform in [SupportedPlatformEnum.WINDOWS_32, SupportedPlatformEnum.WINDOWS_64]:
            return self.src_path / "out32" / "ssleay32.lib"
        else:
            return self.src_path / "libssl.a"

    @property
    def exe_path(self) -> Path:
        if self.platform in [SupportedPlatformEnum.WINDOWS_32, SupportedPlatformEnum.WINDOWS_64]:
            return self.src_path / "out32" / "openssl.exe"
        else:
            return self.src_path / "apps" / "openssl"


class ModernOpenSslBuildConfig(OpenSslBuildConfig):
    @property
    def _openssl_git_tag(self) -> str:
        return "OpenSSL_1_1_1s"

    _OPENSSL_CONF_CMD = (
        "perl Configure {target} zlib no-zlib-dynamic no-shared enable-rc5 enable-md2 enable-gost "
        "enable-cast enable-idea enable-ripemd enable-mdc2 --with-zlib-include={zlib_include_path} "
        "--with-zlib-lib={zlib_lib_path} enable-weak-ssl-ciphers enable-tls1_3 {extra_args} no-async"
    )

    def _run_build_steps(self, ctx: Context) -> None:
        if self.platform in [SupportedPlatformEnum.WINDOWS_32, SupportedPlatformEnum.WINDOWS_64]:
            ctx.run("nmake clean", warn=True)
            ctx.run("nmake")
        else:
            return super()._run_build_steps(ctx)

    @property
    def libcrypto_path(self) -> Path:
        if self.platform in [SupportedPlatformEnum.WINDOWS_32, SupportedPlatformEnum.WINDOWS_64]:
            return self.src_path / "libcrypto.lib"
        else:
            return self.src_path / "libcrypto.a"

    @property
    def libssl_path(self) -> Path:
        if self.platform in [SupportedPlatformEnum.WINDOWS_32, SupportedPlatformEnum.WINDOWS_64]:
            return self.src_path / "libssl.lib"
        else:
            return self.src_path / "libssl.a"

    @property
    def include_path(self) -> Path:
        return self.src_path / "include"

    @property
    def exe_path(self) -> Path:
        if self.platform in [SupportedPlatformEnum.WINDOWS_32, SupportedPlatformEnum.WINDOWS_64]:
            return self.src_path / "apps" / "openssl.exe"
        else:
            return self.src_path / "apps" / "openssl"


class ZlibBuildConfig(BuildConfig):
    @property
    def src_tar_gz_url(self) -> str:
        return "https://www.zlib.net/fossils/zlib-1.2.13.tar.gz"

    @property
    def src_path(self) -> Path:
        return _DEPS_PATH / "zlib-1.2.13"

    def build(self, ctx: Context) -> None:
        if self.platform in [SupportedPlatformEnum.WINDOWS_32, SupportedPlatformEnum.WINDOWS_64]:
            if self.platform == SupportedPlatformEnum.WINDOWS_32:
                build_platform = "Win32"
            else:
                build_platform = "x64"

            # Assuming default path for Visual Studio 2022
            msbuild_path = Path(
                "C:\\Program Files\\Microsoft Visual Studio\\2022\\Enterprise\\MSBuild\\Current\\Bin\\MSBuild.exe"
            )
            assert msbuild_path.exists()

            vs_contrib_path = self.src_path / "contrib" / "vstudio"
            with ctx.cd(str(vs_contrib_path)):
                ctx.run(
                    f'"{msbuild_path}" vc14\\zlibvc.sln /P:Configuration=Release /P:Platform={build_platform}'
                )

        else:
            # Linux/macOS build
            with ctx.cd(str(self.src_path)):
                ctx.run('CFLAGS="-fPIC" ./configure -static')
                ctx.run("make clean")
                ctx.run("make")

    @property
    def libz_path(self) -> Path:
        if self.platform in [SupportedPlatformEnum.WINDOWS_32, SupportedPlatformEnum.WINDOWS_64]:
            arch = "x86" if self.platform == SupportedPlatformEnum.WINDOWS_32 else "x64"
            zlib_lib_path = (
                self.src_path / "contrib" / "vstudio" / "vc14" / arch / "ZlibStatRelease" / "zlibstat.lib"
            )
        else:
            zlib_lib_path = self.src_path / "libz.a"
        return zlib_lib_path

    @property
    def include_path(self) -> Path:
        return self.src_path


@task
def build_zlib(ctx, do_not_clean=False):
    print("ZLIB: Starting...")
    zlib_cfg = ZlibBuildConfig(CURRENT_PLATFORM)
    if not do_not_clean:
        zlib_cfg.clean()
        zlib_cfg.fetch_source()
    zlib_cfg.build(ctx)
    print("ZLIB: All done")


@task
def build_legacy_openssl(ctx, do_not_clean=False):
    print("OPENSSL LEGACY: Starting...")
    ssl_legacy_cfg = LegacyOpenSslBuildConfig(CURRENT_PLATFORM)
    if not do_not_clean:
        ssl_legacy_cfg.clean()
        ssl_legacy_cfg.fetch_source()
    zlib_cfg = ZlibBuildConfig(CURRENT_PLATFORM)
    ssl_legacy_cfg.build(ctx, zlib_lib_path=zlib_cfg.libz_path, zlib_include_path=zlib_cfg.include_path)
    print("OPENSSL LEGACY: All done")


@task
def build_modern_openssl(ctx, do_not_clean=False):
    print("OPENSSL MODERN: Starting...")
    ssl_modern_cfg = ModernOpenSslBuildConfig(CURRENT_PLATFORM)
    if not do_not_clean:
        ssl_modern_cfg.clean()
        ssl_modern_cfg.fetch_source()
    zlib_cfg = ZlibBuildConfig(CURRENT_PLATFORM)
    ssl_modern_cfg.build(ctx, zlib_lib_path=zlib_cfg.libz_path, zlib_include_path=zlib_cfg.include_path)
    print("OPENSSL MODERN: All done")


@task
def build_nassl(ctx):
    """Build the nassl C extension."""
    extra_args = ""
    if CURRENT_PLATFORM == SupportedPlatformEnum.WINDOWS_32:
        extra_args = "--plat-name=win32"
    elif CURRENT_PLATFORM == SupportedPlatformEnum.WINDOWS_64:
        extra_args = "--plat-name=win-amd64"

    # Reset the ./build folder if there was a previous version of nassl
    build_path = Path(__file__).parent.absolute() / "build"
    if build_path.exists():
        shutil.rmtree(build_path)

    ctx.run(f"python setup.py build_ext -i {extra_args}")


@task
def build_deps(ctx, do_not_clean=False):
    """Build the C libraries the nassl C extension depends on."""
    build_zlib(ctx, do_not_clean)
    build_legacy_openssl(ctx, do_not_clean)
    build_modern_openssl(ctx, do_not_clean)


@task
def build_all(ctx, do_not_clean=False):
    """Build the nassl C extension and the C libraries from scratch."""
    build_deps(ctx, do_not_clean)
    build_nassl(ctx)

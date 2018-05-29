import shutil
import tarfile
from abc import ABC, abstractmethod
from enum import Enum
from pathlib import Path
from tempfile import TemporaryFile
from platform import architecture
from sys import platform

try:
    from invoke import task
except ImportError:
    # This will happen when doing pip install nassl in an environment that does not have invoke pre-installed
    # We still want this script to be usable directly by pip
    def task(*args, **kwargs):
        # Return a function - anything will do
        return repr


# Where we store the src packages of OpenSSL and Zlib
_DEPS_PATH = Path(__file__).parent.absolute() / 'deps'


class SupportedPlatformEnum(Enum):
    """Platforms supported by nassl.
    """
    OSX_64 = 1
    LINUX_64 = 2
    LINUX_32 = 3
    WINDOWS_32 = 4
    WINDOWS_64 = 5
    OPENBSD_64 = 6


CURRENT_PLATFORM = None
if architecture()[0] == '64bit':
    if platform == 'darwin':
        CURRENT_PLATFORM = SupportedPlatformEnum.OSX_64
    elif platform in ['linux', 'linux2']:
        CURRENT_PLATFORM = SupportedPlatformEnum.LINUX_64
    elif platform == 'win32':
        CURRENT_PLATFORM = SupportedPlatformEnum.WINDOWS_64
    elif platform == 'openbsd5':
        CURRENT_PLATFORM = SupportedPlatformEnum.OPENBSD_64
elif architecture()[0] == '32bit':
    if platform in ['linux', 'linux2']:
        CURRENT_PLATFORM = SupportedPlatformEnum.LINUX_32
    elif platform == 'win32':
        CURRENT_PLATFORM = SupportedPlatformEnum.WINDOWS_32


class BuildConfig(ABC):

    def __init__(self, platform):
        self.platform = platform

    @property
    @abstractmethod
    def src_path(self):
        """Where the src package is extracted to before trying to build it.
        """
        pass

    @property
    @abstractmethod
    def src_tar_gz_url(self):
        """Where to download src package from.
        """
        pass

    def fetch_source(self):
        """Download the tar archive that contains the source code for the library.
        """
        import requests  # Do not import at the top that this file can be imported by setup.py
        with TemporaryFile() as temp_file:
            # Download the source archive
            request = requests.get(self.src_tar_gz_url)
            temp_file.write(request.content)
            # Rewind the file
            temp_file.seek(0)
            # Extract the content of the archive
            tar_file = tarfile.open(fileobj=temp_file)
            tar_file.extractall(path=_DEPS_PATH)

    @abstractmethod
    def build(self, ctx):
        pass

    @property
    @abstractmethod
    def include_path(self):
        pass


class OpenSslBuildConfig(BuildConfig, ABC):

    @property
    @abstractmethod
    def _openssl_git_tag(self):
        pass

    @property
    def src_tar_gz_url(self):
        return f'https://github.com/openssl/openssl/archive/{self._openssl_git_tag}.tar.gz'

    @property
    def src_path(self):
        return _DEPS_PATH / f'openssl-{self._openssl_git_tag}'

    def _get_build_target(self, should_build_for_debug):
        if self.platform == SupportedPlatformEnum.WINDOWS_32:
            openssl_target = 'VC-WIN32'
        elif self.platform == SupportedPlatformEnum.WINDOWS_64:
            openssl_target = 'VC-WIN64A'
        elif self.platform == SupportedPlatformEnum.OSX_64:
            openssl_target = 'darwin64-x86_64-cc'
        elif self.platform == SupportedPlatformEnum.LINUX_64:
            openssl_target = 'linux-x86_64'
        elif self.platform == SupportedPlatformEnum.LINUX_32:
            openssl_target = 'linux-elf'
        else:
            raise ValueError('Unknown platform')

        if should_build_for_debug:
            if self.platform not in [SupportedPlatformEnum.WINDOWS_32, SupportedPlatformEnum.WINDOWS_64]:
                raise ValueError('Debug builds only supported for Windows')
            else:
                openssl_target = f'debug-{openssl_target}'

        return openssl_target

    def build(self, ctx, zlib_lib_path=None, zlib_include_path=None, should_build_for_debug=False):
        if not zlib_lib_path or not zlib_include_path:
            raise ValueError('Missing argument')

        # Build OpenSSL
        openssl_target = self._get_build_target(should_build_for_debug)
        with ctx.cd(str(self.src_path)):
            self._run_configure_command(ctx, openssl_target, zlib_lib_path, zlib_include_path)
            self._run_build_steps(ctx)

    # To be defined in subclasses
    _OPENSSL_CONF_CMD = None

    def _run_configure_command(self, ctx, openssl_target, zlib_lib_path, zlib_include_path):
        if self.platform in [SupportedPlatformEnum.WINDOWS_32, SupportedPlatformEnum.WINDOWS_64]:
            extra_args = '-no-asm -DZLIB_WINAPI'  # *hate* zlib
        else:
            extra_args = ' -fPIC'

        ctx.run(self._OPENSSL_CONF_CMD.format(
            target=openssl_target,
            zlib_lib_path=zlib_lib_path,
            zlib_include_path=zlib_include_path,
            extra_args=extra_args
        ))

    def _run_build_steps(self, ctx):
        if self.platform in [SupportedPlatformEnum.WINDOWS_32, SupportedPlatformEnum.WINDOWS_64]:
            if self.platform == SupportedPlatformEnum.WINDOWS_32:
                ctx.run('ms\\do_ms')
            else:
                ctx.run('ms\\do_win64a.bat')

            ctx.run('nmake -f ms\\nt.mak clean', warn=True)  # Does not work if tmp32 does not exist (fresh build)
            ctx.run('nmake -f ms\\nt.mak')

        else:
            ctx.run('make clean', warn=True)
            ctx.run('make build_libs')  # Only build the libs as it is faster - not available on Windows


class LegacyOpenSslBuildConfig(OpenSslBuildConfig):

    @property
    def _openssl_git_tag(self):
        return 'OpenSSL_1_0_2e'

    _OPENSSL_CONF_CMD = (
        'perl Configure {target} zlib no-zlib-dynamic no-shared enable-rc5 enable-md2 enable-gost '
        'enable-cast enable-idea enable-ripemd enable-mdc2 --with-zlib-include={zlib_include_path} '
        '--with-zlib-lib={zlib_lib_path} {extra_args}'
    )

    @property
    def include_path(self):
        if self.platform in [SupportedPlatformEnum.WINDOWS_32, SupportedPlatformEnum.WINDOWS_64]:
            return self.src_path / 'inc32'
        else:
            return self.src_path / 'include'

    @property
    def libcrypto_path(self):
        if self.platform in [SupportedPlatformEnum.WINDOWS_32, SupportedPlatformEnum.WINDOWS_64]:
            return self.src_path / 'out32' / 'libeay32.lib'
        else:
            return self.src_path / 'libcrypto.a'

    @property
    def libssl_path(self):
        if self.platform in [SupportedPlatformEnum.WINDOWS_32, SupportedPlatformEnum.WINDOWS_64]:
            return self.src_path / 'out32' / 'ssleay32.lib'
        else:
            return self.src_path / 'libssl.a'


class ModernOpenSslBuildConfig(OpenSslBuildConfig):

    @property
    def _openssl_git_tag(self):
        return 'OpenSSL_1_1_1-pre6'

    _OPENSSL_CONF_CMD = (
        'perl Configure {target} zlib no-zlib-dynamic no-shared enable-rc5 enable-md2 enable-gost '
        'enable-cast enable-idea enable-ripemd enable-mdc2 --with-zlib-include={zlib_include_path} '
        '--with-zlib-lib={zlib_lib_path} enable-weak-ssl-ciphers enable-tls1_3 {extra_args} no-async'
    )

    def _run_build_steps(self, ctx):
        if self.platform in [SupportedPlatformEnum.WINDOWS_32, SupportedPlatformEnum.WINDOWS_64]:
            ctx.run('nmake clean', warn=True)
            ctx.run('nmake build_libs')
        else:
            return super()._run_build_steps(ctx)

    @property
    def libcrypto_path(self):
        if self.platform in [SupportedPlatformEnum.WINDOWS_32, SupportedPlatformEnum.WINDOWS_64]:
            return self.src_path / 'libcrypto.lib'
        else:
            return self.src_path / 'libcrypto.a'

    @property
    def libssl_path(self):
        if self.platform in [SupportedPlatformEnum.WINDOWS_32, SupportedPlatformEnum.WINDOWS_64]:
            return self.src_path / 'libssl.lib'
        else:
            return self.src_path / 'libssl.a'

    @property
    def include_path(self):
        return self.src_path / 'include'


class ZlibBuildConfig(BuildConfig):

    @property
    def src_tar_gz_url(self):
        return 'http://zlib.net/zlib-1.2.11.tar.gz'

    @property
    def src_path(self):
        return _DEPS_PATH / 'zlib-1.2.11'

    def build(self, ctx):
        if self.platform in [SupportedPlatformEnum.WINDOWS_32, SupportedPlatformEnum.WINDOWS_64]:
            if self.platform == SupportedPlatformEnum.WINDOWS_32:
                arch = 'x86'
                build_script = 'bld_ml32.bat'
                build_platform = 'Win32'
            else:
                arch = 'x64'
                build_script = 'bld_ml64.bat'
                build_platform = 'x64'

            masm_path = self.src_path / 'contrib' / f'masm{arch}'
            with ctx.cd(str(masm_path)):
                ctx.run(build_script)
                ctx.run( f'msbuild ..\\vstudio\\vc14\\zlibvc.sln /P:Configuration=Release /P:Platform={build_platform}')

        else:
            # Linux/macOS build
            with ctx.cd(str(self.src_path)):
                ctx.run('CFLAGS="-fPIC" ./configure -static')
                ctx.run('make clean')
                ctx.run('make')

    @property
    def libz_path(self):
        if self.platform in [SupportedPlatformEnum.WINDOWS_32, SupportedPlatformEnum.WINDOWS_64]:
            arch = 'x86' if self.platform == SupportedPlatformEnum.WINDOWS_32 else 'x64'
            zlib_lib_path = self.src_path / 'contrib' / 'vstudio' / 'vc14' / arch / 'ZlibStatRelease' / 'zlibstat.lib'
        else:
            zlib_lib_path = self.src_path / 'libz.a'
        return zlib_lib_path

    @property
    def include_path(self):
        return self.src_path


@task
def build_zlib(ctx):
    print('ZLIB: Starting...')
    zlib_cfg = ZlibBuildConfig(CURRENT_PLATFORM)
    zlib_cfg.fetch_source()
    zlib_cfg.build(ctx)
    print('ZLIB: All done')


@task
def build_legacy_openssl(ctx):
    print('OPENSSL LEGACY: Starting...')
    ssl_legacy_cfg = LegacyOpenSslBuildConfig(CURRENT_PLATFORM)
    ssl_legacy_cfg.fetch_source()
    zlib_cfg = ZlibBuildConfig(CURRENT_PLATFORM)
    ssl_legacy_cfg.build(ctx, zlib_lib_path=zlib_cfg.libz_path, zlib_include_path=zlib_cfg.include_path)
    print('OPENSSL LEGACY: All done')


@task
def build_modern_openssl(ctx):
    print('OPENSSL MODERN: Starting...')
    ssl_modern_cfg = ModernOpenSslBuildConfig(CURRENT_PLATFORM)
    ssl_modern_cfg.fetch_source()
    zlib_cfg = ZlibBuildConfig(CURRENT_PLATFORM)
    ssl_modern_cfg.build(ctx, zlib_lib_path=zlib_cfg.libz_path, zlib_include_path=zlib_cfg.include_path)
    print('OPENSSL MODERN: All done')


@task
def build_nassl(ctx):
    extra_args = ''
    if CURRENT_PLATFORM == SupportedPlatformEnum.WINDOWS_32:
        extra_args = '--plat-name=win32'
    elif CURRENT_PLATFORM == SupportedPlatformEnum.WINDOWS_64:
        extra_args = '--plat-name=win-amd64'

    # Reset the ./build folder if there was a previous version of nassl
    build_path = Path(__file__).parent.absolute() / 'build'
    if build_path.exists():
        shutil.rmtree(build_path)

    ctx.run(f'python setup.py build_ext -i {extra_args}')


@task(pre=[build_zlib, build_legacy_openssl, build_modern_openssl, build_nassl])
def build_all(ctx):
    pass

from pathlib import Path
import shutil

from invoke import task, Collection, Context

import build_config
from nassl import __version__

root_path = Path(__file__).parent.absolute()


@task
def test(ctx: Context) -> None:
    ctx.run("pytest --durations 5")
    ctx.run("python sample_client.py")


@task
def lint(ctx: Context) -> None:
    ctx.run("ruff format .")
    ctx.run("ruff check . --fix")
    ctx.run("mypy build_config.py sample_client.py nassl tests")


@task
def package_linux_wheels(ctx: Context) -> None:
    """Build the Linux 32 and 64 bit wheels using Docker."""
    ctx.run(f"docker run --rm -v {root_path}:/io quay.io/pypa/manylinux2010_i686 bash /io/build_linux_wheels.sh")
    ctx.run(f"docker run --rm -v {root_path}:/io quay.io/pypa/manylinux2010_x86_64 bash /io/build_linux_wheels.sh")


@task
def package_wheel(ctx: Context) -> None:
    """Build the binary wheel for the current system; works on Windows anc macOS."""
    ctx.run("python setup.py bdist_wheel")


@task
def package_windows_wheels(ctx: Context) -> None:
    """Build the binary wheels for Windows; this expects Python to be installed at specific locations."""
    for python_exe in [
        "%userprofile%\\AppData\\Local\\Programs\\Python\\Python37\\python.exe",
        "%userprofile%\\AppData\\Local\\Programs\\Python\\Python38\\python.exe",
    ]:
        ctx.run(f"{python_exe} setup.py bdist_wheel")


@task
def release(ctx: Context) -> None:
    raise NotImplementedError()
    response = input(f'Release version "{__version__}" ? y/n')
    if response.lower() != "y":
        print("Cancelled")
        return

    # Ensure the tests pass
    test(ctx)

    # Add the git tag
    ctx.run(f"git tag -a {__version__} -m '{__version__}'")
    ctx.run("git push --tags")

    # Build the Windows wheel
    package_wheel(ctx)

    # Build the Linux wheels
    package_linux_wheels(ctx)


# Setup all the tasks
ns = Collection()
ns.add_task(release)
ns.add_task(test)
ns.add_task(lint)


package = Collection("package")
package.add_task(package_linux_wheels, "linux_wheels")
package.add_task(package_windows_wheels, "windows_wheels")
package.add_task(package_wheel, "wheel")
ns.add_collection(package)

build = Collection("build")


@task
def build_zlib(ctx: Context, do_not_clean: bool = False) -> None:
    print("ZLIB: Starting...")
    assert build_config.CURRENT_PLATFORM
    zlib_cfg = build_config.ZlibBuildConfig(build_config.CURRENT_PLATFORM)
    if not do_not_clean:
        zlib_cfg.clean()
        zlib_cfg.fetch_source()
    zlib_cfg.build(ctx)
    print("ZLIB: All done")


@task
def build_legacy_openssl(ctx: Context, do_not_clean: bool = False) -> None:
    print("OPENSSL LEGACY: Starting...")
    assert build_config.CURRENT_PLATFORM
    ssl_legacy_cfg = build_config.LegacyOpenSslBuildConfig(build_config.CURRENT_PLATFORM)
    if not do_not_clean:
        ssl_legacy_cfg.clean()
        ssl_legacy_cfg.fetch_source()
    zlib_cfg = build_config.ZlibBuildConfig(build_config.CURRENT_PLATFORM)
    ssl_legacy_cfg.build(ctx, zlib_lib_path=zlib_cfg.libz_path, zlib_include_path=zlib_cfg.include_path)
    print("OPENSSL LEGACY: All done")


@task
def build_modern_openssl(ctx: Context, do_not_clean: bool = False) -> None:
    print("OPENSSL MODERN: Starting...")
    assert build_config.CURRENT_PLATFORM
    ssl_modern_cfg = build_config.ModernOpenSslBuildConfig(build_config.CURRENT_PLATFORM)
    if not do_not_clean:
        ssl_modern_cfg.clean()
        ssl_modern_cfg.fetch_source()
    zlib_cfg = build_config.ZlibBuildConfig(build_config.CURRENT_PLATFORM)
    ssl_modern_cfg.build(ctx, zlib_lib_path=zlib_cfg.libz_path, zlib_include_path=zlib_cfg.include_path)
    print("OPENSSL MODERN: All done")


@task
def build_nassl(ctx: Context) -> None:
    """Build the nassl C extension."""
    extra_args = ""
    if build_config.CURRENT_PLATFORM == build_config.SupportedPlatformEnum.WINDOWS_32:
        extra_args = "--plat-name=win32"
    elif build_config.CURRENT_PLATFORM == build_config.SupportedPlatformEnum.WINDOWS_64:
        extra_args = "--plat-name=win-amd64"

    # Reset the ./build folder if there was a previous version of nassl
    build_path = Path(__file__).parent.absolute() / "build"
    if build_path.exists():
        shutil.rmtree(build_path)

    ctx.run(f"python setup.py build_ext -i {extra_args}")


@task
def build_deps(ctx: Context, do_not_clean: bool = False) -> None:
    """Build the C libraries the nassl C extension depends on."""
    build_zlib(ctx, do_not_clean)
    build_legacy_openssl(ctx, do_not_clean)
    build_modern_openssl(ctx, do_not_clean)


@task
def build_all(ctx: Context, do_not_clean: bool = False) -> None:
    """Build the nassl C extension and the C libraries from scratch."""
    build_deps(ctx, do_not_clean)
    build_nassl(ctx)


build.add_task(build_zlib, "zlib")
build.add_task(build_legacy_openssl, "legacy_openssl")
build.add_task(build_modern_openssl, "modern_openssl")
build.add_task(build_nassl, "nassl")
build.add_task(build_deps, "deps")
build.add_task(build_all, "all")
ns.add_collection(build)

from pathlib import Path

from invoke import task, Collection

import build_tasks
from nassl import __version__

root_path = Path(__file__).parent.absolute()


@task
def test(ctx):
    # Run linters
    ctx.run("mypy sample_client.py")
    ctx.run("flake8")
    ctx.run("black . --check")

    # Run the test suite
    ctx.run("pytest --durations 5")

    ctx.run("python sample_client.py")


@task
def package_linux_wheels(ctx):
    """Build the Linux 32 and 64 bit wheels using Docker."""
    ctx.run(
        f"docker run --rm -v {root_path}:/io quay.io/pypa/manylinux2010_i686 bash /io/build_linux_wheels.sh"
    )
    ctx.run(
        f"docker run --rm -v {root_path}:/io quay.io/pypa/manylinux2010_x86_64 bash /io/build_linux_wheels.sh"
    )


@task
def package_wheel(ctx):
    """Build the binary wheel for the current system; works on Windows anc macOS."""
    ctx.run("python setup.py bdist_wheel")


@task
def package_windows_wheels(ctx):
    """Build the binary wheels for Windows; this expects Python to be installed at specific locations."""
    for python_exe in [
        "%userprofile%\\AppData\\Local\\Programs\\Python\\Python37\\python.exe",
        "%userprofile%\\AppData\\Local\\Programs\\Python\\Python38\\python.exe",
    ]:
        ctx.run(f"{python_exe} setup.py bdist_wheel")


@task
def release(ctx):
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


package = Collection("package")
package.add_task(package_linux_wheels, "linux_wheels")
package.add_task(package_windows_wheels, "windows_wheels")
package.add_task(package_wheel, "wheel")
ns.add_collection(package)

build = Collection("build")
build.add_task(build_tasks.build_zlib, "zlib")
build.add_task(build_tasks.build_legacy_openssl, "legacy_openssl")
build.add_task(build_tasks.build_modern_openssl, "modern_openssl")
build.add_task(build_tasks.build_nassl, "nassl")
build.add_task(build_tasks.build_all, "all")
ns.add_collection(build)

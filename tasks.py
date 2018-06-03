from pathlib import Path

from invoke import task
from nassl import __version__

root_path = Path(__file__).parent.absolute()


@task
def test(ctx):
    # Run the test suite
    ctx.run('pytest')

    # Run linters
    ctx.run('mypy nassl')
    # TODO(AD): Enable once we move to python 3 type annotations
    ctx.run('flake8 nassl')


@task
def build_linux_wheels(ctx):
    # Build the Linux 32 and 64 bit wheels using Docker
    ctx.run(f'docker run --rm -v {root_path}:/io quay.io/pypa/manylinux1_i686 bash /io/build_linux_wheels.sh')
    ctx.run(f'docker run --rm -v {root_path}:/io quay.io/pypa/manylinux1_x86_64 bash /io/build_linux_wheels.sh')


@task
def build_wheel(ctx):
    # Works on Windows anc macOS
    ctx.run('python setup.py bdist_wheel')


@task
def release(ctx):
    raise NotImplementedError()
    response = input(f'Release version "{__version__}" ? y/n')
    if response.lower() != 'y':
        print('Cancelled')
        return

    # Ensure the tests pass
    test(ctx)

    # Add the git tag
    ctx.run(f"git tag -a {__version__} -m '{__version__}'")
    ctx.run('git push --tags')

    # Build the Windows wheel
    build_wheel(ctx)

    # Build the Linux wheels
    build_linux_wheel(ctx)


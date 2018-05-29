from pathlib import Path

from invoke import task
from nassl import __version__

root_path = Path(__file__).parent.absolute()


@task
def test(ctx):
    # Run the test suite
    ctx.run('pytest')

    # Run linters
    ctx.run('flake8 sslyze')
    ctx.run('mypy sslyze')


@task
def build_ext(ctx):
    ctx.run('python setup.py build_ext -i')


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
    ctx.run('python setup.py bdist_wheel')

    # Build the Linux 32 and 64 bit wheels using Docker
    ctx.run(f'docker run --rm -v {root_path}:/io quay.io/pypa/manylinux1_i686 bash /io/build_linux_wheels.sh')
    ctx.run(f'docker run --rm -v {root_path}:/io quay.io/pypa/manylinux1_x86_64 bash /io/build_linux_wheels.sh')

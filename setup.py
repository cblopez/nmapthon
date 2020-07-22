from setuptools import setup, find_packages


def get_description():
    with open('README.md') as f:
        return f.read()

setup(
    name='nmapthon',
    version='1.1.1',
    packages=['nmapthon'],
    url='https://github.com/cblopez/nmapthon',
    license='GNUv3',
    author='cblopez',
    author_email='noeroiff@protonmail.com',
    description='A high level Nmap module for Python',
    long_description=get_description(),
    keywords=['python', 'python3', 'nmap', 'module', 'scan', 'nse', 'port', 'service']
)

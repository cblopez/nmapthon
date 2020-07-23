from setuptools import setup, find_packages

with open('README.md') as f:
    setup(
        name='nmapthon',
        version='1.1.1',
        packages=['nmapthon'],
        url='https://github.com/cblopez/nmapthon',
        license='GLPv3',
        author='cblopez',
        author_email='noeroiff@protonmail.com',
        description='A high level Nmap module for Python',
        long_description=f.read(),
        long_description_content_type='text/markdown',
        keywords=['python', 'python3', 'nmap', 'module', 'scan', 'nse', 'port', 'service']
    )

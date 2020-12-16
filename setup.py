from setuptools import setup

with open('README.md') as f:
    setup(
        name='nmapthon',
        version='1.6.3',
        packages=['nmapthon'],
        url='https://github.com/cblopez/nmapthon',
        license='GLPv3',
        author='cblopez',
        author_email='cbarrallopez@gmail.com',
        description='A high level Nmap module for Python',
        long_description=f.read(),
        long_description_content_type='text/markdown',
        classifiers=[
            'Development Status :: 4 - Beta',
            'Programming Language :: Python :: 3 :: Only',
            'Topic :: System :: Networking',
            'Topic :: Software Development :: Libraries :: Python Modules'
        ],
        keywords=['python', 'python3', 'nmap', 'module', 'scan', 'nse', 'port', 'service']
    )

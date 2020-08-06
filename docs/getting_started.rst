Getting started
===============

Nmapthon is a Python module that allows you to interact with the Nmap tool and even extend its capabilities with
Python functions. With this module you will be able to:

* Execute Nmap scans and easily retrieve all the results.
* Execute Nmap scans asynchronously.
* Merge different scanner objects, allowing to easily build multiprocessed, multithreaded and distributed applications.
* Register Python functions as if they were NSE scripts.

Installation
------------
The module requires an updated version of `Nmap <https://nmap.org/>`_ installed on the system. To install Nmapthon, simply use the `pip` package manager::

    # If your pip command corresponds to Python 3
    pip install nmapthon

    # If you use pip3 instead
    pip3 install nmapthon

.. warning::

    Python 2 is not supported.
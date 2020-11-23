Instantiation
=============


The ``NmapScanner`` class takes one positional parameter and ``**kwargs`` parameters for instantiation:

``NmapScanner(targets, ports=None, arguments=None, engine=None)``

- ``targets``: Can be specified as a ``str`` or a ``list``. A string may contain any number of targets separated by commas, and a list may contain any number of targets as separate elements. Nmapthon considers a target any of the following:

    - A domain or URL.
    - A resolvable hostname (like a NetBIOS hostname).
    - A single IP Address (like ``"192.168.2.45"``).
    - A full IP Address range (like ``"192.168.0.2-192.168.0.17"``).
    - A partial IP Address range (like ``"192.167-168.0.1-20"``).
    - An IP address with a netmask, which will include all the IP address inside the mask but without the network address and the broadcast address (like ``"192.168.0.0/24"``).

For ``kwargs``:

- ``ports``: Can be specified as a ``str`` or a ``list``. A list may contain any number of target ports separated by commas, and a list may contain any number of target ports as separate elements. Nmapthon considers a target port any of the following:

    - A single port as ``str`` or ``int`` type (like ``22`` or ``"80"``).
    - A port range (like ``"22-80"``).

- ``arguments``: String containing every nmap parameter that we want to execute. For example ``'-sV -Pn'``.

.. note:: No ``-d`` or ``-v`` options allowed (That means no debugging or verbosity). The ``-p`` parameter is not allowed either, ports must be specified on instantiation or by the ``ports`` setter as explained above.

- ``engine``: Specify a ``PyNSEEngine`` object. Refer to this section :doc:`nmap_engine` to learn more about it.

Note that every instantiation parameter can be set as ``None``, including the ``targets``, but at least those need to be set before running the scan. Each of these instantiation parameters have their properties and setters, which means that you can interact with them after instantiation the scanner itself:

- ``<scanner_instance>.targets``: Property and setter for the ``NmapScanner`` targets.
- ``<scanner_instance>.ports``: Property and setter for the ``NmapScanner`` ports.
- ``<scanner_instance>.arguments``: Property and setter for the ``NmapScanner`` arguments.
- ``<scanner_instance>.engine``: Property and setter for the ``NmapScanner`` NSE engine.

Simple example
++++++++++++++

.. code-block:: python

   import nmapthon as nm

   # This instantiates a scanner for localhost and Service Detection on default ports
   scanner = nm.NmapScanner('127.0.0.1', arguments='-sV')

   # This one scans 255 hosts at maximum speed and with script launching, OS detection and Service Detection
   scanner = nm.NmapScanner(['192.168.1.1', '192.168.1.11', '192.168.2.0/24'], arguments='-A -T4')

   # This one scans localhost and another IP range for the first 200 ports and the ones in range 800-1000.
   scanner = nm.NmapScanner('127.0.0.1, 10.10.0.0/16', ports=['1-200', '800-1000'])



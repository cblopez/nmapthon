NmapScanner
===========

.. toctree::
   :titlesonly:
   :maxdepth: 2

   running_scan
   simple_information
   hosts_ports_info
   services
   os_detection
   host_traceroute
   merge

Class for executing and parsing nmap scans.

The ``NmapScanner`` class takes one positional parameter and ``**kwargs`` parameters for instantiation.

Scan targets must be specified as a positional argument in two valid formats:

- In ``str`` format, targets can be a network/netmask like ``'192.168.1.0/24'``, a range like ``'192.168.1.1-192.168.1.10'``, a number of individual targets separated by a comma like ``'192.168.1.1,192.168.1.2'``, a single target like ``'192.168.1.1'`` or any combination between these options like ``'192.168.1.1-192.168.1.10, 192.168.1.22'``.
- In ``list`` format, with every IP Address specified separately: ``['192.168.1.1', '192.168.1.2', .... ]``.

On the other hand, ``kwargs`` are:

- ``ports``: Specify the ports to scan in two different accepted formats.

  - In ``str`` format, specify a port range like ``'20-100'``, a number of individual ports separated by a comma like ``'22,53'``, a single port like ``'22'`` or any combination between these options like ``'22,53,100-300'``.
  - In ``list`` format, built by single int or str port values: ``[22, 53, 100]`` or ``['22', '53', '100']``.

- ``arguments``: String containing every nmap parameter that we want to execute. For example ``'-sV -Pn'``.

.. note:: No ``-d`` or ``-v`` options allowed (That means no debugging or verbosity). The ``-p`` parameter is not allowed either, ports must be specified on instantiation or by the `ports` setter as explained above. **No IP addresses will be allowed**, targets must be specified on instantiation or by the ``targets`` setter as explained above.

- ``name``: Specify a particular name for the scanner.
- ``engine``: Specify a ``PyNSEEngine`` object. Refer to this section :doc:`nmap_engine` to learn more about it.

Example
+++++++

.. code-block:: python

   import nmapthon as nm

   # This instantiates a scanner for localhost and Service Detection on default ports
   scanner = nm.NmapScanner('127.0.0.1', arguments='-sV')

   # This one scans 3 hosts at maximum speed and with script launching, OS detection and Service Detection
   scanner = nm.NmapScanner(['192.168.1.1', '192.168.1.11', '192.168.1.34'], arguments='-A -T4')

   # This one scans localhost, SYN scan for the first 200 ports. His name is 'Mapy'
   scanner = nm.NmapScanner('127.0.0.1', name='Mapy', ports=list(range(1,201)))

Errors
++++++

During instantiation, some errors can be raised:

- ``InvalidArgumentError``: For example, if ``arguments`` contains the ``-p`` parameter, this will be raised.
- ``MalformedIPAddressError``: If a target is not well written (it is not a valid IP address), this will be raised.
- ``InvalidPortError``: If string port cannot be converted to integer, it is a non valid port. If a port is smaller than 1 or greater than 65535. Will be raised in any of these cases.

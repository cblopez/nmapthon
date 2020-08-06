Host Scripts & Traceroute
=========================

We can gather the information from the scripts that are host oriented. If looking for service oriented scripts, you can find them in :doc:`services`:

- ``host_scripts(host:str, script_name=None)``: **Yield** every name and output for every script launched against the host. If ``script_name`` is set to a string, only the scripts containing that string will be yielded, i.e. ``sc.host_scripts('127.0.0.1', script_name='smtp')``.

Get every hop information from executing a traceroute to a particular host:

- ``trace_info(host:str)``: **Yields** one ``TraceHop`` instance per traceroute hop.
  
TraceHop object
+++++++++++++++

A ``TraceHop`` instance has four basic properties to access its information:

- ``ttl``: Time-To-Live. IP layer field.  
- ``ip_addr``: IP Address of the node.  
- ``rtt``: Round Trip Time.  
- ``domain_name``: Domain name of the node.  
  
``TraceHop`` instances have a custom ``__str__`` method to print their information in a specific way.

.. note::

    If any of the traceroute hop information is unknown, the corresponding property will return ``None``.

.. note::

    If a ``TraceHop`` instance has no information (blocked by firewall, for example) the  ``__str__`` method will print ``'Somehow blocked Hop.'``.

Host scripts example
++++++++++++++++++++

.. code-block:: python

    import nmapthon as nm

    scanner = nm.NmapScanner('192.168.1.1-192.168.1.112', arguments='-A')
    scanner.run()

    for host in scanner.scanned_hosts():
        print("Host: {}".format(host))
        for name, output in scanner.host_scripts(host):
            print("Script: {}\nOutput: {}".format(name, output))
  
Traceroute example
++++++++++++++++++

.. code-block:: python

    import nmapthon as nm

    scanner = nm.NmapScanner('85.65.234.12', arguments='--traceroute')
    scanner.run()

    if '85.65.234.12' in scanner.scanned_hosts():
        for tracehop_instance in scanner.trace_info('85.65.234.12'):
            print('TTL: {}\tIP address: {}'.format(tracehop_instance.ttl, tracehop_instance.ip_addr))


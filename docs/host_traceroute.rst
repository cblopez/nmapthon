Traceroute
==========

We can get every hop information from executing a traceroute to a particular host:

- ``trace_info(host:str)``: **Yields** one ``TraceHop`` instance per traceroute hop.
  
TraceHop object
+++++++++++++++

A ``TraceHop`` instance has four basic properties to access its information:

- ``ttl``: Time-To-Live. IP layer field.  
- ``ip_addr``: IP Address of the node.  
- ``rtt``: Round Trip Time.  
- ``domain_name``: Domain name of the node.  

.. note::

    If any of the traceroute hop information is unknown, the corresponding property will return ``None``.

Traceroute example
++++++++++++++++++

.. code-block:: python

    import nmapthon as nm

    scanner = nm.NmapScanner('85.65.234.12', arguments='--traceroute')
    scanner.run()

    if '85.65.234.12' in scanner.scanned_hosts():
        for tracehop_instance in scanner.trace_info('85.65.234.12'):
            print('TTL: {}\tIP address: {}'.format(tracehop_instance.ttl, tracehop_instance.ip_addr))


Scripts
=======

Nmapthon supports two types of scripts:
    - NSE scripts. Which are LUA scripts that can be execute through the ``--script`` argument from the nmap tool.
    - PyNSE scripts. Which are python functions that are registered as "NSE scripts". See :doc:`nmap_engine` to learn how they work.

Whatever type of script you are executing, each script has a name. In case of NSE scripts, the script name will be the argument(s) passed to the ``--script`` argument like ``--script ssl-cert``.
On the other hand, PyNSE scripts have a mandatory ``name`` parameter.

When retrieving a script output, it needs to be referenced by its name. Nmapthon has several ways of retrieving those scripts:

    - ``host_script(host:str, script_name:str)``: Returns the host script output for a given script name. If the target does not have any information about that script, it will raise a ``NmapScannerError``.

    - ``port_script(host:str, proto:str, port:(str,int), script_name:str)``: Returns the port script output for a given script name, associated with a protocol and a port. If the target does not have any information about that script, it will raise a ``NmapScannerError``.

    - ``host_scripts(host:str, script_name:str=None)``: Yields a tuple with ``(script_name, script_output)`` for every host script from a particular host. If ``script_name`` is specified, then it will only yield scripts whose names **contain** that string.

    - ``port_scripts(host:str, proto:str, port:(str,int), script_name:str=None)``: Yields a tuple with ``(script_name, script_output)`` for every port script from a particular host, port and protocol. If ``script_name`` is specified, then it will only yield scripts whose names **contain** that string.

.. note::

    ``host_script()`` and ``port_script()`` functions must raise a ``NmapScannerError`` to indicate "missing" scripts. The ``None`` return value is not possible,
    since a PyNSE script may return a None value if the user defines it to do so, and may confuse the real script output with the "missing script" situation.

.. note::

    Apart from that, we can get the scripts from a ``Service`` instance, as explained in the previous page.


Example
+++++++

.. code-block:: python

    import nmapthon as nm

    sc = nm.NmapScanner('10.10.10-15.2-254', ports=[443, 80, 53], arguments='-sV --script=ssl-cert,dns-brute')
    sc.run()
    for i in sc.scanned_hosts():
        for port in sc.scanned_ports(i, 'tcp'):
            for n, o in sc.port_scripts(i, 'tcp', port):
                print('Name: {}\nOutput: {}'.format(n, o))

    # Check unique script output
    print('{}'.format(sc.port_script('10.10.10.4', 'tcp', 443, 'ssl-cert')))

    # Check unique script from service
    service_example = sc.service('10.10.10.4', 'tcp', 443)
    if service_example is not None:
        print('{}'.format(service_example['ssl-cert']))

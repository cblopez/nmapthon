Port scripts
============

Port scripts are those that execute when a particular port responds to the nmap scan.

To register a port script, decorate the functions with ``@<engine_instance>.port_script(...)``. The function is defined as follows:

``port_script(name:str, port:(str,int,list), targets='*', proto='*', states=None, args=None)``:

- ``name``: Name that will be used on the ``NmapScanner`` instance to reference the script output.
- ``ports``: Single port or list of ports that, when found with the given states, will make the engine execute the function. They are specified the same way as ports are specified during the ``NmapScanner`` :doc:`instantiation`.
- ``targets``: Specify the targets that will be affected by the function. ``'*'`` means all of them. Targets can be specified as an ``str`` or a ``list`` type, the same way as targets are specified during the ``NmapScanner`` :doc:`instantiation`.
- ``proto``: Transport layer protocol from the port. Default is ```*'`` which means anyone, but can also be ``'tcp'`` or ``'udp'``.
- ``states``: Port states when the function will be triggered. Default is ``None``, which means only ``'open'`` state, but can be a ``list`` containing any of the following values: ``'open'``, ``'filtered'`` and ``'closed'``.
- ``args``: If the function has arguments, pass them as a ``tuple`` or ``list`` of arguments.

The information gathered from each of the registered port function is stored inside a ``Service`` object from that particular port. If there ``NmapScanner`` has already generated a ``service`` instance for that port, the script will be added to it.

**Note that the data that will be stored inside the instance will be whatever the decorated function returns**

Example
+++++++

.. code-block:: python

    import nmapthon as nm

    engine = nm.engine.PyNSEEngine()

    # Create a custom SSH enum function
    @engine.port_script('custom_ssh_enum', 22, proto='tcp', states=['open', 'filtered'], args=('path/to/wordlist',))
    def ssh_enum_function(wordlist):
        return 'My SSH enum with the wordlist: {}'.format(wordlist)

    sc = nm.NmapScanner('127.0.0.1', ports='22', arguments='-sV -Pn -sS -n', engine=engine)
    sc.run()

    # If the gateway responds to the scan, it will have an assigned port script
    print(sc.port_script('127.0.0.1', 'tcp', 22, 'custom_ssh_enum'))

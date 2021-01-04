Import XML
==========

You can build an ``NmapScanner`` object from an existing Nmap XML file. To do so, just execute the ``from_xml(file)`` constructor:

- ``NmapScanner.from_xml(file:str)``: Returns a ``NmapScanner`` instance from a valid Nmap XML output file.

.. note::

    Note that ``non_scanned_targets()`` and ``non_scanned_ports(target:str, proto:str)`` will both
    return empty values, since Nmapthon uses the <instance>.targets and <instance>.ports setters, respectively,
    to process which targets and ports are not scanned.

Example
+++++++

.. code-block:: python

    import nmapthon as nm

    scanner = nm.NmapScanner.from_xml('/path/to/nmap.xml')
    # Of course, you do NOT call the run() method

    for i in scanner.scanned_hosts():
        for proto in scanner.all_protocols(i):
            print('Continue normally....')


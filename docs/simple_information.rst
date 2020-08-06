
Getting simple scan information
===============================

After calling the ``run()`` method, the ``NmapScanner`` instance will have several properties to access scan information, only if no errors are raised. These properties are:

- ``start_timestamp``: Get the timestamp from when the scan started.
- ``start_time``: Get the human-readable date and hour from when the scan started.
- ``exit_status``: Nmap application exit status.
- ``args``: All arguments used in the scan, **but this args are printed by nmap**.
- ``summary``: Scan summary.
- ``version``: Nmap's version.
- ``end_timestamp``: Get the timestamp from when the scan finished.
- ``end_time``: Get the human-readable date and hour from when the scan finished.
- ``finished``: Boolean flag that tells if the scan has finished.
- ``tolerant_errors``: String with errors that happened during the Nmap execution but let the scan finish.

.. important:: If any of this properties is accessed before calling the ``run()`` method, they will return ``None``.

Example
-------

.. code-block:: python

    import nmapthon as nm

    scanner = nm.NmapScanner('192.168.1.0/24', ports='1-1024', arguments='-sS')
    scanner.run()

    # If program reaches this point, we can get the properties.
    print("Started at: {}".format(scanner.start_time))
    print("Used {} nmap version.".format(scanner.version))
    print("The tolerant errors were:\n{}".format(scanner.tolerant_errors))
    # You can keep calling any of this properties
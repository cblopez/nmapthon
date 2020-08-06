
Running the scan
================

After instantiating the scanner, the ``run()`` method will execute it. The program will block until the nmap process finishes, and after that, the ``NmapScanner`` instance will contain all the information from the scan.

Example
+++++++

.. code-block:: python

    import nmapthon as nm

    example_scanner = nm.NmapScanner(target='127.0.0.1', arguments='-sS')

    # Execute the scan
    try:
        example.scanner.run()
    except nm.NmapScanError as e:
        print('Catching all scan errors!: {}'.format(e))

    # Now the 'example_scanner' object contains all the information from the scan.

Please head to the next sections to know how to manage all the information gathered from the scan.

Errors
++++++

When executing the ``run()`` method, several type of errors can pop, but all of them are raised by the same Exception: ``NmapScanError``. The situations when this Exception could come out are:

- No targets to scan are specified.
- When nmapthon cannot parse the nmap output, due to any type of nmap error that interrupted the execution. In this case, the ``NmapScannerError`` will print the nmap error.
- When no output from nmap is given. Should never happen but if it does, the ``NmapScannerError`` will print the nmap error.
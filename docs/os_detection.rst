OS Detection  
============

If OS detection was performed (for example, by using ``'-O'`` or ``'-A'``), you can get the OS matches with their accuracy and the OS fingerprint:

- ``os_matches(host:str)``: **Yields** every OS name with it's corresponding accuracy for a given host.  
- ``os_fingerprint(host:str)``: Returns the OS fingerprint for a given host. If no fingerprint was found or performed, it will return ``None``.
- ``most_accurate_os(host:str)``: Returns a list with the most accurate OSs. **The list is needed because there might not be only one OS match with the highest accuracy, but several.**  

OS Detection example
++++++++++++++++++++

.. code-block:: python

    import nmapthon as nm

    scanner = nm.NmapScanner('127.0.0.1', arguments='-O --osscan-guess')
    scanner.run()

    # Notice that '127.0.0.1' can be used without expecting an NmapScanError
    # localhost should always respond.
    for os_match, acc in scanner.os_matches('127.0.0.1'):
        print('OS Match: {}\tAccuracy:{}%'.format(os_match, acc))

    fingerprint = scanner.os_fingerprint('127.0.0.1')
    if fingerprint is not None:
        print('Fingerprint: {}'.format(fingerprint))

    for most_acc_os in scanner.most_accurate_os('127.0.0.1'):
        print('Most accurate OS: {}'.format(most_acc_os))
Merging NmapScanner objects
===========================

There may be situations where several ``NmapScanner`` instances may be instantiated separately, so a ``merge()`` is available to
merge scans. It must be called after the instance finishes the scan, and it accepts any number of other ``NmapScanner`` instances 
plus additional ``**kwargs``:

- ``merge_tcp=True``: Flag to allow TCP merging
- ``merge_udp=True``: Flag to allow UDP merging 
- ``merge_scripts=True``: Flag to merge host scripts. TCP/UDP port scripts are merged if their respective flag is ``True``.
- ``merge_trace=True``: Merge Traceroute information. 
- ``merge_os=True``: Merge OS information.  
- ``merge_non_scanned=True``: Merge IPs that could not be scanned.

``merge()`` deep inspect
++++++++++++++++++++++++

The ``merge()`` method acts differently depending on a main condition, which is: "Does the instance that's calling the method have the target X?". Depending on the answer:

- If the target is not in the caller scanner, all the information from the target is copied depending on the ``**kwargs`` flags values.
- If the target is on the caller scanner, the information is copied depending on the flags, particularly:

  - TCP/UDP ports are copied if they where not scanned on the caller scan, but if the caller already has information about them, it's not overwritten.
  - OS information, as well as Host scripts are checked one by one, only adding them if the caller does not have information of a particular OS/script.
  - Traceroute is only added while no Traceroute information is in the caller scanner.  

Example 1: Dividing TCP and UDP scans
+++++++++++++++++++++++++++++++++++++

.. code-block:: python

    import nmapthon as nm

    # Run a TCP scan synchronously and a UDP async to the same target
    main_scanner = nm.NmapScanner('10.10.10.2', ports=[22, 80, 443], arguments='-sV -sS -n')
    udp_scanner = nm.AsyncNmapScanner('10.10.10.2', ports=[21, 53], arguments='-sU -n', mute_error=True)

    # Launch the UDP first
    udp_scanner.run()

    # Launch the TCP
    try:
        main_scanner.run()
    except nm.NmapScanError as e:
        print('Error while scanning TCP ports:\n{}'.format(e))

    # Wait until UDP ends
    udp_scanner.wait()

    if udp_scanner.finished_successfully():
        # Merge the scans (Do not need to set all flags to False since there is no information on the UDP scanner,
        # but just to show the usage thay are set to False here
        main_scanner.merge(udp_scanner, merge_os=False, merge_scripts=False, merge_tcp=False, merge_trace=False)


Example 2: Multi-threading/processing scans
+++++++++++++++++++++++++++++++++++++++++++

.. code-block:: python

    import nmapthon as nm
    import multiprocessing

    def read_ips(ips_file):
        with open(ips_file) as f:
            return [x.strip() for x in f.readlines()]

    def worker(n, ip, return_dict):
        sc = nm.NmapScanner(ip, ports=[1-1000], arguments='-sT -sV -T4 -n')
        try:
            sc.run()
        except nm.NmapScanner as e:
            raise e
        return_dict[n] = sc


    if __name__ == '__main__':
        # Create share dict to store scans
        manager = multiprocessing.Manager()
        return_dict = manager.dict()
        jobs = []
        # Read IPS from file
        ips = read_ips('my_ips_file.txt')
        for i in range(len(ips)):
            p = multiprocessing.Process(target=worker, args=(i, ips[i], return_dict))
            jobs.append(p)
            p.start()

        # Freeze application until all apps finish
        for proc in jobs:
            proc.join()

        # Take the first scanner as caller
        main_scan = return_dict[0]
        # Pass the rest of the scans as arguments for merging
        main_scan.merge(*list(return_dict.values())[1:])

        # Now you can use the main_scan as a single scanner with all the information
        for host in main_scan:
            # Continue normally
Hosts and ports
===============

After running the scan, we can execute two primary methods to obtain the hosts from the scan:

- ``scanned_hosts()``: Returns a list of scanned hosts.  
- ``non_scanned_hosts()``: Returns a list with all the hosts that where specified on ``targets`` but did not appear on the nmap output, which means that they were not scanned.
  
To get the **hostnames** associated with a particular host:

- ``hostnames(host:str)``: Returns a list with all the hostnames from a host.

Having the scanned hosts, we can get their state, reason and scanned protocols:

- ``state(host:str)``: Returns the state of a given host.  
- ``reason(host:str)``: Returns the reason why the host has a certain state.  
- ``all_protocols(host:str)``: **Yields** every protocol scanned for a given host.  

For a given host and protocol, we can also get the scanned and non scanned ports, plus their state:

- ``scanned_ports(host:str, protocol:str)``: Return a list of scanned ports for a given host and protocol.  
- ``non_scanned_ports(host:str, protocol:str``: Return a list of non scanned ports for a given host and protocol.  
- ``port_state(host:str, protocol:str, port:str,int)``: Return the state and reason ``tuple`` from a port.

.. note::

    If scanning domains, their information would not be under the domain name itself, but under an IP Address, which is the IP address of the host gathered by nmap after resolving the domain.


Host information example
++++++++++++++++++++++++

.. code-block:: python

    import nmapthon as nm

    sc = nm.NmapScanner(['127.0.0.1', '192.168.1.99'], ports=[1,101], arguments='-sT')
    sc.run()

    # Loop through protocols, for every scanned host and get other information
    for host in sc.scanned_hosts():
        # Get state, reason and hostnames
        print("Host: {}\tState: {}\tReason: {}".format(host, sc.state(host), sc.reason(host))
        print("Hostname: {}".format(','.join(sc.hostnames(host))))
        # Get scanned protocols
        for proto in sc.all_protocols(host):
            # Get scanned ports
            for port in sc.scanned_ports(host, proto):
                state, reason = sc.port_state(host, proto, port)
                print("Port: {0:<7}State:{1:<9}Reason:{2}".format(port, state, reason))

  

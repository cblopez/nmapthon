
Services
========

If service detection was performed (for example with ``'-sV'`` or ``'-A'``), we can gather the service information for a given host, protocol and port:

- ``service(host:str, protocol:str, port:str,int)``: Get a Service instance representing the gathered information from the service, if no service information was found it returns ``None``.
- ``standard_service_info(host:str, protocol:str, port:str,int)``: Returns the service name and service information. The service information is a string formed by the service product, version and extrainfo. If there is no info about a particular service, two `None` values will be returned. If nmap has found the name of the service, but it doesnt know anything about the service information itself, this method will return the name and an empty string (``''``).

Service object
++++++++++++++

Executing the function ``service(host:str, protocol:str, port:int,str)`` will return ``None`` if there is no known service, or it will return a ``Service`` object in any other case. A ``Service`` object has 4 simple properties:

- ``name``: Return the name of the service.
- ``product``: Return the product running on that service.
- ``version``: Return the version of the product.
- ``extrainfo``: Return extra information about the product.

We can also get all CPEs associated with that service:

- ``all_cpes()``: Return a list containing all the CPEs from a service.

Get all the scripts information that were launched against that particular service:

- ``all_scripts()``: **Yields** every script name and output from every script that was launched against that service.

Service instances can be used as list objects, which allows scripts management, for example:

- ``service_instance[script_name]``: Return the output from a given script name.
- ``service_instance[script_name] = script_output``: Add a script name with an associated output.
- ``del service_instance[script_name]``: Delete every script related information for a given script name.
- ``'my_script' in service_instance``: Check if a given script is inside the instance.

It also have a custom ``__str__`` method:

- ``print(str(service_instance))``: Prints all the service info in a specific way.

Service object example
++++++++++++++++++++++

.. code-block:: python

    import nmapthon as nm

    scanner = nm.NmapScanner('192.168.1.0/24', ports='22,53,443', arguments='-A -T4')
    scanner.run()

    # for every host scanned
    for host in scanner.scanned_hosts():
        # for every protocol scanned for each host
        for proto in scanner.all_protocols(host):
            # for each scanned port
            for port in scanner.scanned_ports(host, proto):
                # Get service object
                service = scanner.service(host, proto, port)
                if service is not None:
                    print("Service name: {}".format(service.name))
                    print("Service product: {}".format(service.product))
                    for cpe in service.all_cpes():
                        print("CPE: {}".format(cpe))
                    for name, output in service.all_scripts():
                        print("Script: {}\nOutput: {}".format(name, output))
                    # You could also do print(str(service))
                    # You could also know if 'ssh-keys' script was launched and print the output
                    if 'ssh-keys' in service:
                        print("{}".format(service['ssh-keys']))


Service standard info example
+++++++++++++++++++++++++++++

.. code-block:: python

    import nmapthon as nm

    scanner = nm.NmapScanner('192.168.1.0/24', ports='22,53,443', arguments='-sV -T4')
    scanner.run()

    # for every host scanned
    for host in scanner.scanned_hosts():
        # for every protocol scanned for each host
        for proto in scanner.all_protocols(host):
            # for each scanned port
            for port in scanner.scanned_ports(host, proto):
                # Get service information
                service, service_info = scanner.standard_service_info(host, proto, port)
                if service is not None:
                    print("Service: {}\tInfo: {}".format(service, service_info))
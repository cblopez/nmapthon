Host scripts
============

Host scripts are functions that are execute once per host, if they respond to the scan.

To register a host script, decorate the functions with ``@<engine_instance>.host_script('name')``. The function is defined as follows:

``host_script(name:str, target='*', args=None)``:

- ``name``: Name that will be used on the ``NmapScanner`` instance to reference the script output.
- ``target``: Specify the targets that will be affected by the function. ``'*'`` means all of them. It accepts a single target in ``str`` format or a list of them in a ``list`` or ``tuple``.
- ``args``: If the function has arguments, pass them as a ``tuple`` or ``list`` of arguments.

The information gathered from each of the registered host function is stored as a normal host script inside the ``NmapScanner`` instance. To access them, use the ``host_scripts(host:str)`` function.

**Note that the data that will be stored inside the instance will be whatever the decorated function returns**

Example 1
+++++++++

.. code-block:: python

    import nmapthon as nm

    engine = nm.engine.PyNSEEngine()

    # This function will only execute when the gateway (192.168.0.1) responds to the scan.
    @engine.host_script('custom_script', targets='192.168.0.1')
    def custom_gateway_scan():
        return 'I could return any type of information here'

    sc = NmapScanner('192.168.0.0/24', arguments='-sS -n -T5', engine=engine)
    sc.run()

    # If the gateway responds to the scan, it will have an assigned host script
    for name, output in sc.host_scripts('192.168.0.1'):
        print('{}: {}'.format(name, output))
        # Prints 'custom_script: I could return any type of information here!'

Example 2
+++++++++

.. code-block:: python

    import nmapthon as nm

    engine = nm.engine.PyNSEEngine()

    # Pass the function parameters with the decorator
    @engine.host_script('param_testing', args=('Nmapthon',))
    def func_with_params(my_arg):
        return 'Testing {}!'.format(my_arg)

    sc = NmapScanner('127.0.0.1', engine=engine)
    sc.run()

    # Localhost should always respond
    for _, output in sc.host_scripts('127.0.0.1'):
        print('{}'.format(output))
        # Prints 'Testing Nmapthon!'
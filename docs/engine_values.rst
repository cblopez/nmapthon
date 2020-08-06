Accessing values
================

When the engine functions are executed, you may want to access some execution time values that are being handled by the ``NmapScanner`` object at that point. For that purpose you can use the following ``PyNSEEngine`` instance properties:

- ``current_target``: Returns the target being processed when the function is executed
- ``current_port``\*: Returns the port being processed when the function is executed.
- ``current_proto``\*: Returns the transport layer protocol being processed when the function is executed.
- ``current_state``\*: Returns the state of the port being processed when the function is executed.

\* *These properties are only suitable if the function is decorated as a port script.*

.. important::

    Any of the above properties will return ``None`` if they are not handled by the appropriate decorator. i.e. ``current_port`` returns ``None`` if the function is decorated by ``host_script``.

Example
+++++++

.. code-block:: python

    import nmapthon as nm
    import socket

    engine = nm.engine.PyNSEEngine()

    @engine.port_script('smtp_banner', 25, states=['open', 'filtered'])
    def get_smtp_banner():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Each time the port script executes, it will execute with the current target and port
        s.connect((engine.current_target, engine.current_port))
        banner = s.recv(1024)[4:]
        s.close()
        return banner

    sc = nm.NmapScanner('127.0.0.1', arguments='-sV',  engine=engine)
    smtp_service = sc.service('127.0.0.1', 'tcp', 25)
    if smtp_service is not None:
        print('Here is your SMTP banner: {}'.format(smtp_service['smtp_banner']))
 
Running the scan  
================

``AsyncNmapScanner`` also has the ``run()`` method, which will start executing the scan in background. You can use several methods to get the scan state and block the application:

- ``is_running()``: Returns ``True`` if the scanner is running, ``False`` if not.
- ``wait()``: Blocks the program execution until the scan finishes.  
- ``finished_succesfully()``: Returns ``True`` if the scan finished with no fatal errors. ``False`` if not.
  
If ``mute_errors=True`` is used, you can get the Exception raised when muted in case it did not finish successfully:

- ``fatal_error()``: Returns an ``NmapScanError`` with the information from the Exception raised that was muted. If no ``mute_errors=True`` was set, it will return ``None``, but you will have anyways an ``NmapScanError`` raised on your program.

Example 1
+++++++++

.. code-block:: python

    import nmapthon as nm
    import time

    scanner = nm.AsyncNmapScanner('192.168.1.2', ports=range(1,10001), arguments='-sS -sU')
    scanner.run()

    # Do something while it executes
    while scanner.is_running():
        print("I print because I can :)")
        time.sleep(1)

    # Check if it was not successful
    if not scanner.finished_succesfully():
        print("Uh oh! Something went wrong!")
  
Example 2
+++++++++

.. code-block:: python

    import nmapthon as nm

    scanner = nm.AsyncNmapScanner('192.168.1.2', ports=range(1,10001), arguments='-sS -sU')
    scanner.run()

    # Do something and block execution until finishes
    for i in range(1, 1000000):
        print("Im printing a lot of lines!")
    scanner.wait()

    # Check if it was not successful
    if not scanner.finished_succesfully():
        print("Uh oh! Something went wrong!\nPopped error:\n{}".format(scanner.fatal_error()))
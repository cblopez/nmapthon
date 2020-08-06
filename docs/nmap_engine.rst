PyNSEEngine
===========

.. toctree::
   :titlesonly:
   :maxdepth: 1

   engine_host_script
   engine_port_script
   engine_values
   engine_oop

Any ``NmapScanner`` object may receive a ``PyNSEEngine`` object, where several functions can be registered as host or port scripts.

Functions are registered by using **decorators**.

.. note::

    Although the engine registers functions, they are referenced as "scripts". That's because the PyNSEEngine emulates a Python extension of the Nmap Scripting Engine (NSE).

A simple example:

.. code-block:: python

    import nmapthon as nm

    engine = nm.engine.PyNSEEngine()

    @engine.host_script('my_script')
    def example():
        print('My own function as a script!')
        return None

    sc = nm.NmapScanner('127.0.0.1', engine=engine)


.. important::

    All the functions registered in the ``PyNSEEngine`` will be executed once the scan finishes, as opposed to the NSE scripts that are executed when the corresponding host/port is found open
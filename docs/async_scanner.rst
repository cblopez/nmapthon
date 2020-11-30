AsyncNmapScanner
================

.. toctree::
   :titlesonly:
   :maxdepth: 1

   running_scan_async

Instantiating ``AsyncNmapScanner`` has the same ``**kwargs`` as the ``NmapScanner`` class (:doc:`instantiation`), but this one has an optional extra ``kwargs`` parameter:

- ``mute_errors``: A boolean type parameter, ``False`` by default. If set to ``True``, the scanner won't show fatal errors when executing.
- ``wrapper``: Wrapper class for executing the background scan. By default, this value is ``multiprocessing.Process`` to avoid GIL problems, but you can specify ``threading.Thread`` if needed.
  
Example
+++++++

.. code-block:: python

    import nmapthon as nm

    async_scanner = nm.AsyncNmapScanner('10.126.65.0/23', ports='21,22,100-200', arguments='-sV -n -T4')

    # Async Scanner with error muting
    async_scanner = nm.AsyncNmapScanner('192.168.1.30', arguments='-A -T4', mute_errors=True)

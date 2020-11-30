Errors
======

The nmapthon error hierarchy is the following::

| NmapScanError
|__ InvalidPortError
|__ MalformedIpAddressError
|__ InvalidArgumentError
| EngineError

Any error related with the Nmap scanner will be raised under an ``NmapScanError`` or any child error, while any error related to registering Python functions into the ``PyNSEEngine`` will raise an ``EngineError``. All the Exception classes are imported automatically when ``import nmapthon`` executes, but you can also find them under ``nmapthon.exceptions``.
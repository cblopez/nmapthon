Object Oriented Engine
======================

Depending on the application architecture, it may be messy to write different functions in the middle of the code, without relating them with any class at all (in case of an Object Oriented project).

This page contains an example of how Python classes could be used to wrap the ``PyNSEEngine``.

Example
-------

- ``engine_gen.py``

.. code-block:: python

    import nmapthon.engine as eng


    class EngineGenerator:

        _ENGINE = eng.PyNSEEngine()

        @classmethod
        def generate_engine(cls):

            cls._ENGINE.host_script('name_1')
            def first():
                return 'First'

            cls._ENGINE.port_script('name_2', [80, 443])
            def second():
                return 'Potential HTTP server at: {}:{}'.format(cls._ENGINE.current_target,
                                                                cls._ENGINE.current_port)

            # Any number of additional functions
            return cls._ENGINE


- ``main.py``

.. code-block:: python

    import sys
    import nmapthon as nm

    from engine_gen import EngineGenerator

    if __name__ == '__main__':
        sc = nm.NmapScanner(sys.argv[1], engine=EngineGenerator.generate_engine())
        sc.run()

        # ETC
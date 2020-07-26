#!/usr/bin/env python

# Copyright (c) 2019 Christian Barral

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from inspect import signature


class EngineError(Exception):
    """ Exception class for PyNSEEngine errors
    """
    def __init__(self, msg):
        super().__init__(msg)


class PyNSEScript:
    """ An individual Python function that is executed as if it were an Nmap NSE script.

    As well as those scripts, they can be host oriented or port oriented. It can have any number of arguments and
    it can assign output to the NmapScanner object. The functions are only executed if the port or host (depending
    on the function type) is open, but the user can also specify which of the three port states ('open', 'filtered'
    or 'closed') are valid for the function to execute.

        :param name: Name of the function (PyNSEScript name)
        :param func: Function to execute
        :param port: Port or ports to target. A None value means it is a host script
        :param proto: Transport layer protocol ('tcp', 'udp' or '*' for both)
        :param args: Arguments for the function
        :param states: List of states valid for function execution
        :type name: str
        :type func: function
        :type port: str, int, list
        :type args: list, tuple
        :type states: list, tuple
    """

    def __init__(self, name, func, port, proto, args, states):
        self.name = name
        self.func = func
        self.port = port
        self.proto = proto
        self.args = args
        self.states = states

    @property
    def name(self):
        return self._name

    @property
    def func(self):
        return self._func

    @property
    def port(self):
        return self._port

    @property
    def proto(self):
        return self._proto

    @property
    def args(self):
        return self._args

    @property
    def states(self):
        return self._states

    @name.setter
    def name(self, v):
        self._name = v

    @func.setter
    def func(self, v):
        if not callable(v):
            raise EngineError('Function parameter is not callable: {}'.format(v))

        self._func = v

    @port.setter
    def port(self, v):
        if v is None:
            self._port = v
        elif isinstance(v, str):
            try:
                int_v = int(v)
            except ValueError:
                raise EngineError('Invalid port value: {}'.format(v))
            else:
                if not 1 <= int_v <= 65535:
                    raise EngineError('Invalid port value, out of range: {}'.format(int_v))

        elif isinstance(v, int):
            if not 1 <= v <= 65535:
                raise EngineError('Invalid port value, out of range: {}'.format(v))

        elif isinstance(v, list):
            try:
                int_ports = map(int, v)
            except ValueError:
                raise EngineError('Invalid port values')
            else:
                if not all([1 <= x <= 65535 for x in int_ports]):
                    raise EngineError('Out of range ports inside ports list')

        else:
            raise EngineError('Invalid port data type: {}'.format(type(v)))

        self._port = v

    @proto.setter
    def proto(self, v):
        if v is None:
            self._proto = None
        elif v.lower() in ['tcp', 'udp', '*']:
            self._proto = v.lower()
        else:
            raise EngineError('Invalid proto value: {}'.format(v))

    @args.setter
    def args(self, v):
        if v is None:
            self._args = []
        else:
            number_args = len(str(signature(self.func)).split(','))
            if not isinstance(v, list) and not isinstance(v, tuple):
                raise EngineError('Invalid args data type: {}'.format(type(v)))
            if number_args != len(v):
                raise EngineError('Number of function arguments does not match with specified arguments')

            self._args = v

    @states.setter
    def states(self, v):

        if v is None:
            self._states = v

        elif not all(x in ['open', 'closed', 'filtered'] for x in v):
            raise EngineError('PyNSEScript states must be "open", "closed" or "filtered".')

        else:
            self._states = v

    def execute(self):
        """ Runs the function with the specific arguments and returns the output
        """

        return self.func(*self.args)


class PyNSEEngine:
    """ Represents the Nmap NSE script engine. It is used to instantiate an object that is passed to the
    NmapScanner __init__ method and it registers new "NSE scripts", that are function written in Python. These
    functions execute depending on the states defined by the user, and they can be host or port oriented.

    Several decorators are offered to make it easy for the user to include new functions.
    """

    def __init__(self):
        self._was_registered = False

        self.PYNSEScripts = []

    def _register_port_script(self, func, name, port, proto):
        """ Register a given function to execute on a given port

        :param func: Function to register
        :param name: Name of the function
        :param port: Port(s) affected
        :param proto: Protocol for the ports
        :type func: function
        :type name: str
        :type port: str, int, list
        :type proto: str
        """
        self.PYNSEScripts.append(PyNSEScript(name, func, port, proto, None, None))

    def _register_host_script(self, func, name):
        """ Register a given function to execute on a hosts

        :param func: Function to register
        :param name: Name of the function
        :type func: function
        :type name: str
        """
        self.PYNSEScripts.append(PyNSEScript(name, func, None, None, None, None))

    def register_port_script(self, name, port, proto='*'):
        """ A decorator to register the given function into the PyNSEEngine.

        :param name: Name of the function/script to be used later on to retrieve the information gathered by it.
        :param port: Port(s) to be affected by the function
        :param proto: Protocol of the port to be affected by the function
        :type name: str
        :type port: list, int, str
        :type proto: str
        """
        def decorator(f):
            self._register_port_script(f, name, port, proto)
            return f
        return decorator

    def states(self, states):
        """ A decorator to define the states of the port(s) when the function will be executed

        :param states: List of states. Only 'open', 'closed' and 'filtered' are valid states
        :type states: list
        """

        def decorator(f):
            self.PYNSEScripts[len(self.PYNSEScripts) - 1].states = states
            return f

        return decorator

    def args(self, *args, **kwargs):
        """ A decorator to define the arguments of the function that is being passed to the engine. The arguments
        are passed separately and need to be the same number of arguments needed by the function

        :param args: List of arguments
        :type args: list
        """
        def decorator(f):
            self.PYNSEScripts[len(self.PYNSEScripts) - 1].args = args
            return f
        return decorator


if __name__ == '__main__':

    engine = PyNSEEngine()

    @engine.states(['open', 'filtered'])
    @engine.args('Nmapthon')
    @engine.register_port_script('my_py_nse_script', 22, proto='tcp')
    def example_func(my_argument):
        return 'Hello World! My arg: {}'.format(my_argument)

    print(engine.PYNSEScripts[0].execute())

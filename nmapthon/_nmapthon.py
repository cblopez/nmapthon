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

import multiprocessing
import subprocess
import threading
import xml.etree.ElementTree as ET

import nmapthon._port_utils as pu
import nmapthon._target_utils as tu

from .engine import PyNSEEngine
from .exceptions import *


class _XMLParser:
    """ XML parser that takes an nmap scan output and parsers all the important information thanks
    to different methods, permitting to access the XML separately. As the XML output depends on debugging
    and verbose levels, the -v and -d arguments are not permitted, to force a standard XML output.

    This class will be used by every NmapScanner(or subclasses) instance to parse it's output and create the network
    profile from that output. Instances attribute MONTH_EQ is a dictionary used to parse String months to a
    numeric value.

        :param xml_string: Variable containing all the XML output
        :type xml_string: str

    note:
        Most of all the XML elements are found using XPath syntax.

    """

    def __init__(self, xml_string=''):
        self.__xml_string = xml_string
        self.__xml_iterable_tree = self.__parse_xml()
        self.__parsed_info = {}
        self.MONTH_EQ = {'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6,
                         'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12}

    @property
    def xml_string(self):
        """ Raw XML string.
        """
        return self.__xml_string

    @property
    def tree(self):
        """ ElementTree from parsing XML string.
        """
        return self.__xml_iterable_tree

    @property
    def parsed_info(self):
        """ Parsed dictionary built from the ElementTree.
        """
        return self.__parsed_info

    @xml_string.setter
    def xml_string(self, value):
        """ xml_string setter.

            :param value: String to assign.
            :type value: str
            :raises: AssertionError
        """
        self.__xml_string = value
        assert isinstance(self.xml_string, str)

    def __parse_xml(self):
        """ Parses a string as an XML tree.

            :return: XML Root Element.
        """
        return ET.fromstring(self.xml_string)

    def __parse_running_info(self):
        """ Parse all general scanning info into a dictionary and assign it to the class attribute __parsed_info
        into the 'running_info' key.
        """

        # Empty dictionary to fill
        parsed_dictionary = {}
        # Loop through every attribute from the root element
        for attribute, value in self.tree.attrib.items():
            # Depending on the attribute, execute one action or another.
            if 'startstr' in attribute:
                # On startstr attribute, format the day, month and year.
                split_date = value.split(' ')
                day = split_date[2]
                month = str(self.MONTH_EQ[split_date[1]])
                year = split_date[4]
                time = split_date[3]
                parsed_dictionary['start_time'] = time + ' ' + '-'.join([day, month, year])
            elif 'start' in attribute:
                parsed_dictionary['start_timestamp'] = value
            elif 'version' in attribute:
                parsed_dictionary['version'] = value
            elif 'args' in attribute:
                parsed_dictionary['args'] = value
            # If the attribute is not important, continue

        # Loop through all elements on the <finished> element
        for attribute, value in self.tree.find('.//finished').attrib.items():
            # Depending on the attribute, execute one action or another.
            if 'summary' in attribute:
                parsed_dictionary['summary'] = value
            elif 'timestr' in attribute:
                # On timestr attribute, format the day, month and year.
                split_date = value.split(' ')
                day = split_date[2]
                month = str(self.MONTH_EQ[split_date[1]])
                year = split_date[4]
                time = split_date[3]
                parsed_dictionary['end_time'] = time + ' ' + '-'.join([day, month, year])
            elif 'time' in attribute:
                parsed_dictionary['end_timestamp'] = value
            elif 'summary' in attribute:
                parsed_dictionary['summary'] = value
            elif 'exit' in attribute:
                parsed_dictionary['exit_status'] = value
            # If the attribute is not important, continue

        # Assign the built dictionary to the 'running_info' key from __parsed_info attribute
        self.parsed_info['running_info'] = parsed_dictionary

    def __parse_scan_info(self):
        """ Parse all scan type related info, including scan types, number of services and services themselves.

            :return: Dictionary with all the scan type info
            :rtype: dict
        """

        # Empty initial dictionary
        parsed_dictionary = {}

        # Find the <scaninfo> element
        scan_info_element = self.tree.find('.//scaninfo')
        current_scan_tag_attributes = scan_info_element.attrib
        # Assign keys and values from the element found
        parsed_dictionary[current_scan_tag_attributes['protocol']] = {
            'type': current_scan_tag_attributes['type'],
            'numservices': current_scan_tag_attributes['numservices'],
            'services': current_scan_tag_attributes['services']
        }

        # Assign the built dictionary to the 'scan_findo' key from __parsed_info attribute
        self.parsed_info['scan_info'] = parsed_dictionary

    def __parse_hosts_info(self):
        """ Parse all host scan related info, including scanned ports, services, hostnames, operating systems and
        script execution results

        note::
            This method operates directly with the __parsed_info attribute, rather than starting, using and assigning
            an initially empty dictionary.
        """

        self.parsed_info['scan'] = {}

        # Loop through every <host> element, which contains very host scan result.
        for host in self.tree.findall('.//host'):
            # IP Address parsing. If host has no ip address, something is wrong.
            try:
                current_ip = host.find('address').attrib['addr']
            except (KeyError, IndexError):
                raise _XMLParsingError('Could not parse host\'s IP address.')

            # Use the IP address as a key, assigning an initially empty dictionary to save all host-related info.
            self.parsed_info['scan'] = {current_ip: {}}

            # Host status parsing. If not state or reason are found, set them to None.
            status_element = host.find('status')
            if status_element is not None:
                self.parsed_info['scan'][current_ip]['state'] = status_element.attrib['state']
                self.parsed_info['scan'][current_ip]['reason'] = status_element.attrib['reason']
            else:
                self.parsed_info['scan'][current_ip]['state'] = None
                self.parsed_info['scan'][current_ip]['reason'] = None

            # Hostnames parsing. Initially set it to an empty list
            hostnames_element = host.find('hostnames')
            self.parsed_info['scan'][current_ip]['hostnames'] = []
            # For each hostnames found, add them to the list. If there is any type of KeyError,
            # something went wrong, just pass.. This loop will only work if any <hostname> element is found.
            for hostname in hostnames_element.findall('hostname'):
                try:
                    self.parsed_info['scan'][current_ip]['hostnames'].append(hostname.attrib['name'])
                except KeyError:
                    pass

            # Port info parsing
            # Create a protocol key into the 'protocols' dictionary. Protocols are taken from the previously
            # parsed 'scan_info' dictionary keys.
            for protocol in self.parsed_info['scan_info']:
                # Add 'protocols' key with every protocol scan inside
                self.parsed_info['scan'][current_ip]['protocols'] = {protocol: {}}

                # Build X-Path predicate, which means 'Find every <port> element inside a <ports> element and has
                # a 'protocol' attribute equal to the current protocol from this loop iteration.
                port_predicate = f".//ports/port[@protocol='{protocol}']"
                # Build X-Path predicate for states, based on the port_predicate, now just find the state element inside
                # the previously gathered <port> element.
                state_predicate = port_predicate + '/state'
                # For each port and port status on that protocol, using the zip() function to loop through them
                # at the same time.
                for port_element, state_element in zip(host.findall(port_predicate), host.findall(state_predicate)):
                    # Assign the state and reason into the dictionary of the current port scanned.
                    # Port service is initially None.
                    self.parsed_info['scan'][current_ip]['protocols'][protocol][port_element.attrib['portid']] = {
                        'state': state_element.attrib['state'],
                        'reason': state_element.attrib['reason']
                    }

                    # Get <service> element inside the <port> element
                    service_element = port_element.find('service')
                    service = None
                    # If there is a service element (Cannot be more than one).
                    if service_element is not None:
                        # Set name, product, version and extrainfo from the service attributes, if they exist
                        # If not, set them to None
                        name = service_element.attrib['name'] \
                            if 'name' in service_element.attrib else None
                        product = service_element.attrib['product'] \
                            if 'product' in service_element.attrib else None
                        version = service_element.attrib['version'] \
                            if 'version' in service_element.attrib else None
                        extrainfo = service_element.attrib['extrainfo'] \
                            if 'extrainfo' in service_element.attrib else None
                        # Create a list of CPEs
                        cpe_list = []
                        # Loop though all <cpe> elements. Do nothing if there are no <cpe> elements
                        for cpe in service_element.findall('.//cpe'):
                            # Add the <cpe> element text to the cpe list, which is the actual cpe
                            cpe_list.append(cpe.text)

                        # Instantiate a Service object with all the information gathered from the service
                        # Please head to the Service class to see more documentation about this.
                        service = Service(name, product, version, extrainfo, cpe_list)

                    # Loop through every <script> tag inside the port, that represents every script launched against
                    # that service, with it's output.
                    if service is not None:
                        for script_element in port_element.findall('script'):
                            # Get script name and output.
                            name, output = None, None
                            # If KeyError, no name on script, so it is malformed. Just continue to the next
                            try:
                                name = script_element.attrib['id']
                            except KeyError:
                                continue

                            # If KeyError, no output given, so just leave it as None.
                            try:
                                output = script_element.attrib['output']
                            except KeyError:
                                pass

                            # Add name and output to the service instance previously created. The Service class
                            # is like a dictionary, please head to the Service class to understand how it works.
                            service[name] = output

                    # Add the service instance to the port information dictionary.
                    # None if there was no <service> element
                    self.parsed_info['scan'][current_ip]['protocols'][protocol][port_element.attrib['portid']][
                        'service'] = service

                # Host scoped scripts. Create an 'scripts' entry and loop through every script launched to
                # the host. Which are the <script> elements inside the <hostscript> element.
                self.parsed_info['scan'][current_ip]['scripts'] = []
                for script_element in host.findall('.//hostscript/script'):
                    # Find script name. If no name is found, malformed somehow, continue.
                    try:
                        script_name = script_element.attrib['id']
                    except KeyError:
                        continue

                    # Get output from script by the <elem> element inside it, if no elem is found, just
                    # copy the 'output' attribute, which is less readable but it's an output after all.
                    # If no elem is found, and a KeyError is raised when searching the output attribute,
                    # set output to None.
                    elem_element = script_element.find('.//elem')
                    if elem_element is not None:
                        script_output = elem_element.text
                    else:
                        try:
                            script_output = script_element.attrib['output']
                        except KeyError:
                            script_output = None

                    # Add script name and output to 'scripts' as a dictionary
                    self.parsed_info['scan'][current_ip]['scripts'].append(
                        {'name': script_name,
                         'output': script_output}
                    )

                # Traceroute information. Create the 'trace' key, which is a list of TraceHop objects
                # sorted from first to last hop. As traceroutes might be uncompleted due to firewalls and/or
                # pure information missing, try if every information exists, and if not,
                # set that particular information to None. Although this might cause an instantiation
                # of a TraceHop object with all it's attributes to None, it's necessary, because a hop
                # with no information doesn't mean that you don't have to count it.
                self.parsed_info['scan'][current_ip]['trace'] = []
                for trace_element in host.findall('.//trace'):
                    try:
                        ttl = int(trace_element.attrib['ttl'])
                    # If attributes does not exists OR int conversion error, set it to None
                    except (KeyError, ValueError):
                        ttl = None

                    try:
                        ip_addr = trace_element.attrib['ipaddr']
                    except KeyError:
                        ip_addr = None

                    try:
                        rtt = float(trace_element.attrib['rtt'])
                    except (KeyError, ValueError):
                        rtt = None

                    try:
                        host = trace_element.attrib['host']
                    except KeyError:
                        host = None

                    # Append the TraceHop object
                    self.parsed_info['scan'][current_ip]['trace'].append(TraceHop(ttl, ip_addr, rtt, host))

                # OS information. Create an 'os' key with a dictionary inside, 'matches' key with a list of
                # os matches, empty at first, and then a 'fingerprint' key, None at first
                self.parsed_info['scan'][current_ip]['os'] = {'matches': [], 'fingerprint': None}
                # For every OS match, append the name and accuracy as a dictionary to the 'matches'.
                # If no OS matches, list remains empty
                for os_match in host.findall('.//osmatch'):
                    self.parsed_info['scan'][current_ip]['os']['matches'].append({
                        'name': os_match.attrib['name'],
                        'accuracy': os_match.attrib['accuracy']
                    })
                # Sort OS Matches in descending order by accuracy
                self.parsed_info['scan'][current_ip]['os']['matches'].sort(key=lambda k: k['accuracy'], reverse=True)

                # OS fingerprint. If no fingerprint is found, just remains None.
                os_fingerprint_element = host.find('.//osfingerprint')
                if os_fingerprint_element is not None:
                    self.parsed_info['scan'][current_ip]['os']['fingerprint'] = \
                        os_fingerprint_element.attrib['fingerprint']

    def parse(self):
        """ Execute all parsing functions and return the hole nested dictionary with the scan information.

            :return: Class attribute with all the info
            :rtype: dict
        """

        self.__parse_running_info()
        self.__parse_scan_info()
        self.__parse_hosts_info()
        return self.parsed_info

    def extract_error_msg(self):
        """ Extracts the error message from the Nmap XML output.

            :returns: Nmap message error
            :rtype: str
        """
        finished_element = self.tree.find('.//finished')
        return finished_element.attrib['errormsg']


class Service:
    """ This class represents a service running on a port, containing all the information
    from a particular service. Service scripts are treated like a dictionary, where the
    script name is the key and the script output is the value

        :param name: Name of the service
        :param product: Product of the service
        :param version: Version of the service
        :param extrainfo: Extra info from the service
        :param cpes: Service CPE
        :param scripts: Scripts information
        :type name: str
        :type product: str
        :type version: str
        :type extrainfo: str
        :type cpes: list
        :type scripts: dict
    """

    def __init__(self, name, product, version, extrainfo, cpes, scripts=None):
        # Solve scripts={} default value causing dictionary mutability
        if scripts is None:
            scripts = dict()
        self.__name = name
        self.__product = product
        self.__version = version
        self.__extrainfo = extrainfo
        self.__cpes = cpes
        self.__scripts = scripts

    @property
    def name(self):
        """ Name of the running service
        """
        return self.__name

    @property
    def product(self):
        """ Product being used on the service.
        """
        return self.__product

    @property
    def version(self):
        """ Version of the product running on the service.
        """
        return self.__version

    @property
    def extrainfo(self):
        """ More info about the product running on the service.
        """
        return self.__extrainfo

    @property
    def scripts(self):
        """ Scripts dictionary.
        """
        return self.__scripts

    def all_cpes(self):
        """ Yields all CPEs from this service

            :return: CPE in string format
            :rtype: str
        """

        for cpe in self.__cpes:
            yield cpe

    def all_scripts(self):
        """ Yields all Scripts names and outputs from this service

            :return: Script name and output
            :rtype: tubple
            WHERE
                name str is the script name
                output str is the script output
        """

        for name, output in self.__scripts.items():
            yield name, output

    def __setitem__(self, name, output):
        """ Add a script name and output to the scripts attribute as a key-value of
        the dictionary

            :param name: Name of the script
            :param output: Name of the script
            :type name: str
            :type output: str
            :raises: AssertionError
        """
        self.__scripts[name] = output

    def __delitem__(self, name):
        """ Delete a script from the instance by the name.

            :param name: Name of the script
            :type name: str
        """

        del self.__scripts[name]

    def __getitem__(self, name):
        """ Get an script output searching by it's name

            :param name: Name of the script
            :type name: str
        """

        return self.__scripts[name]

    def __contains__(self, name):
        """ Returns if script with a given name exists in a service instance.

            :param name: Name of the script
            :type name: str
            :return: True if exists, False if not
            :rtype bool
        """

        return name in self.__scripts


class TraceHop:
    """ This class represents a Traceroute hop.

        :param ttl: IP related Time-To-Leave
        :param ip_addr: IP of the host that redirected the packet.
        :param rtt: Round Trip Time
        :param host: Host's domain name
        :type ttl: int, None
        :type ip_addr: str, None
        :type rtt: float, None
        :type host: str, None
    """

    def __init__(self, ttl, ip_addr, rtt, host):
        self.__ttl = ttl
        self.__ip_addr = ip_addr
        self.__rtt = rtt
        self.__host = host

    @property
    def ttl(self):
        """ Time-To-Leave IP header
        """
        return self.__ttl

    @property
    def ip_addr(self):
        """ Host IP address
        """
        return self.__ip_addr

    @property
    def rtt(self):
        """ Packet Round Trip Time.
        """
        return self.__rtt

    @property
    def domain_name(self):
        """ Host domain name.
        """
        return self.__host


class NmapScanner:
    """ Nmap Scanners super-class, containing all the common logic for every single Scanner that can be created.

    Class attributes represent single pieces of information gathered from the result of the nmap being executed.
    The __result attribute contains the dictionary parsed by the _XMLParser class. The __tolerant_errors attribute
    contains every error from the performed scan that popped but let the scan finish. The __finished attribute is flag
    that tells if the NmapScanner was launched and ended it's execution.

    Every method in this class, apart from the existing properties are used to get information or iterators from
    the resulting information from nmap. Please see repository examples or method docs to know how to use them.

    kwargs parameters:
        name: Name of the NmapScanner instance
        ports: List of ports or string containing them.
        arguments: List of arguments or string containing them.
        engine: PyNSEEngine object used to associate python functions as if they where NSE port/host scripts
    """

    def __init__(self, targets, **kwargs):
        self.name = kwargs.get('name')
        self.targets = targets
        self.ports = kwargs.get('ports')
        self.scan_arguments = kwargs.get('arguments')
        self.engine = kwargs.get('engine', None)
        self._start_timestamp = None
        self._exit_status = None
        self._start_time = None
        self._args = None
        self._summary = None
        self._version = None
        self._end_time = None
        self._end_timestamp = None
        self._scanned_protocols_info = None

        self._result = None
        self._tolerant_errors = None

        self._finished = False

    @property
    def name(self):
        """ Name of the NmapScanner instance
        """
        return self._name

    @property
    def targets(self):
        """ Targets string for nmap.
        """
        return self._targets

    @property
    def ports(self):
        """ Ports string for nmap.
        """
        return self._ports

    @property
    def engine(self):
        """ PyNSEEngine object
        """
        return self._engine

    @property
    def scan_arguments(self):
        """ Aditional scan arguments for nmap.
        """
        return self._scan_arguments

    @property
    def start_timestamp(self):
        """ Starting timestamp from the scan.
        """
        return self._start_timestamp

    @property
    def exit_status(self):
        """ Exit status from the scan.
        """
        return self._exit_status

    @property
    def start_time(self):
        """ Human readable starting time from the scan.
        """
        return self._start_time

    @property
    def args(self):
        """ All nmap arguments summered by nmap output.
        """
        return self._args

    @property
    def summary(self):
        """ Scan summary.
        """
        return self._summary

    @property
    def version(self):
        """ Nmap version.
        """
        return self._version

    @property
    def end_time(self):
        """ Human readble ending t ime from the scan.
        """
        return self._end_time

    @property
    def end_timestamp(self):
        """ Ending timestamp from the scan.
        """
        return self._end_timestamp

    @property
    def tolerant_errors(self):
        """ List of tolerant errors during the scan.
        """
        return self._tolerant_errors

    @property
    def scanned_protocols_info(self):
        """ Dictionary containing info from services and protocols scanned.
        """
        return self._scanned_protocols_info

    @property
    def finished(self):
        """ Flag that tells if the scan has finished.
        """
        return self._finished

    @name.setter
    def name(self, name):
        """ name attribute setter

            :param name: Name of the scanner.
            :type name: str
            :raises: AssertionError
        """
        self._name = name
        assert isinstance(self.name, str) or self.name is None

    @targets.setter
    def targets(self, targets):
        """ targets attribute setter. If a string is passed, the targets property is set to that string and a
        __target_list attribute is created, containing every target parsed as individual values. If a list is passed,
        checks if all targets are valid, if so, create the __target_list attribute set to that list and also set the
        target property to a string containing all targets in the list. comma separated.

            :param targets: Targets list or string
            :type targets: str, list
            :raises: AssertionError
        """
        if targets is None:
            self._targets = None
            self._target_list = None
        elif isinstance(targets, str):
            self._target_list = tu.parse_targets_from_str(targets)
            self._targets = targets
        elif isinstance(targets, list):
            for i in targets:
                if not tu.is_ip_address(i):
                    raise MalformedIpAddressError('Invalid IP Address on setter: {}'.format(i))
            self._target_list = targets
            self._targets = ','.join(self._target_list)
        else:
            raise InvalidArgumentError('Scanner targets must be a string or a list.')

        assert isinstance(self.targets, str) or self.targets is None
        assert isinstance(self._target_list, list) or self._target_list is None

    @ports.setter
    def ports(self, ports):
        """ ports attribute setter. If a string is passed, the ports property is set to that string and a __port_list
        attribute is created, containing every port parsed as integer values. If a list is passed, it builds a 'summary'
        string containing every port in the list interpretable by nmap, then sets the __port_list attribute to that
        passed list.

            :param ports: Port list or string
            :type ports: str, list
            :raises: AssertionError
        """
        if ports is None:
            self._ports = None
            self._port_list = None
        elif isinstance(ports, str):
            self._port_list = pu.parse_ports_from_str(ports)
            self._ports = ports
        elif isinstance(ports, list):
            self._ports = pu.parse_ports_from_list(ports)
            self._port_list = ports
        elif isinstance(ports, int):
            ports = str(ports)
            self._port_list = pu.parse_ports_from_str(ports)
            self._ports = ports
        else:
            raise InvalidArgumentError('Scanner ports must be a string or a lit of ports')

        assert isinstance(self.ports, str) or self.ports is None
        assert isinstance(self._port_list, list) or self._port_list is None

    @scan_arguments.setter
    def scan_arguments(self, arguments):
        """ scan_arguments setter. If a string is passed, it is parsed into a list of string arguments. If a list
        is passed, scan_arguments property is set to that list.

            :param arguments: Arguments list or string
            :type arguments: str, list
            :raises: AssertionError
        """
        if arguments is None:
            self._scan_arguments = []

        elif isinstance(arguments, str):
            self._scan_arguments = self.__parse_arguments(arguments)

        elif isinstance(arguments, list):
            self._scan_arguments = arguments

        else:
            raise InvalidArgumentError('Scanner arguments must be a string or a list of arguments.')

    @engine.setter
    def engine(self, v):
        """ Checks if the value is None or, in other case, a PyNSEEngine instance
        """
        assert isinstance(v, PyNSEEngine) or v is None, 'The Engine must be None or an instance of PyNSEEngine'
        self._engine = v

    def __parse_arguments(self, arguments):
        """ Parses an arguments string into a list of arguments ready to call into subprocess. This parsing
        includes deleting all output, verbose and debugging options.

            :param arguments: String of arguments
            :type arguments: str
            :return: List of arguments
            :rtype: list
            :raises: InvalidArgumentError

        example::
            string                              list
            '-T4 --max-parallelism 255'         ['-T4', '--max-parallelism', '255']
            '-p1-2000 -T2'                      InvalidArgumentError for assigning port range
        """

        # Delete white spaces on sides and change multiple whitespaces with one
        arguments_string = ' '.join(arguments.split())
        # Raise InvalidArgumentError if -p, -v , -d or -o parameter.
        if ' -p' in arguments_string:
            raise InvalidArgumentError('Ports must be specified on instance creation or by instance.ports setter.')

        if ' -v' in arguments_string:
            raise InvalidArgumentError('Scanner does not support verbosity parameter.')

        if ' -d' in arguments_string:
            raise InvalidArgumentError('Scanner does not support debugging parameter.')

        # Split arguments with whitespaces
        arguments_list = arguments_string.split()
        # Check if there is an IP address on the arguments, if so, raise InvalidArgumentError
        if not all(not tu.is_ip_address(p) for p in arguments_list):
            raise InvalidArgumentError(
                'Targets must be specified on instance creation or by instance.targets() setter.')

        return arguments_list

    def run(self):
        """ Runs the nmap command as a terminal process, redirect all the output and errors to variables. Then tries to
        parse the output. If output could not be parsed due to malformed XML then raise a NmapScanError.
        If output could be parsed but there are still errors, save them into de self.tolerant_errors property. After
        that, assign instance attributes and set finished to True.

            :raises: NmapScanError

        IMPORTANTE::
            This method uses the self.ports and self.targets property, which are both strings. This is important,
            because the subprocess.Popen() function receives a list of arguments to execute on terminal, the more
            length the list has, the more it will take. So it is important to summarize the ports and targets into
            a unique string. And that is also the reason why there is a __targets - __target_list and __ports -
            __port_list pair of attributes. One, the property, is a string to send to Popen(), and the other is a
            parsed list from that property string, used in other methods to get information that could not be obtained
            without that info parsed and previously stored.
        """

        # If no targets specified, raise Error
        if self.targets is None or not len(self.targets):
            raise NmapScanError('You must specify targets to scan.')

        # Add the XML output format, build the hole nmap command.
        to_execute = ['nmap', '-oX', '-'] + self.scan_arguments
        # If ports specified, add them as -p parameter, in other case ports will be automatically chosen
        if self.ports is not None:
            to_execute.append('-p' + self.ports)
        # Add the targets
        to_execute.append(self.targets)

        # Call and block a subproccess, then redirect output and errors to a variable each.
        nmap_process = subprocess.Popen(to_execute, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = nmap_process.communicate()
        # If there is output
        if len(output):
            parser = _XMLParser(output)
            try:
                parsed_nmap_output = parser.parse()
            # If parsing error raise NmapScanError with STDERR info.
            except ET.ParseError as e:
                raise NmapScanError('Could not parse output from nmap: {}'.format(e)) from None
            except AttributeError as e:
                raise NmapScanError('Nmap application error: {}'.format(parser.extract_error_msg())) from None

        # If there is no output, raise NmapScanError with STDERR info
        else:
            raise NmapScanError('No output from process was given. STDERR says:\n{}'.format(error.decode('utf8')))

        # If any error but method reaches this point, there are tolerant errors.
        if len(error):
            self._tolerant_errors = error

        # Assign class attributes from the parsed information.
        self._assign_class_attributes(parsed_nmap_output)
        # Execute all the functions that were registered in the engine
        if self.engine is not None:
            self._execute_engine_scripts()
        # Set finished variable to True
        self._finished = True

    def _execute_engine_scripts(self):
        """ Get all host and ports scripts from the PyNSEEngine in case its not None, and execute all its functions.
        """
        for i in self._result:
            for j in self.engine.get_suitable_host_scripts(i):
                self._result[i]['scripts'].append({
                    'name': j.name,
                    'output': j.execute()
                })

            for proto in self._result[i]['protocols']:
                for port in self._result[i]['protocols'][proto]:
                    script_list = [x for x in self.engine.get_suitable_port_scripts(i, 
                                  proto, port, self._result[i]['protocols'][proto][str(port)]['state'])]

                    if len(script_list):
                        try:
                            service_instance = self._result[i]['protocols'][proto][str(port)]['service']
                        except KeyError:
                            service_instance = Service('', '', '', '', [])
                        for k in script_list:
                            service_instance[k.name] = k.execute()

    def _assign_class_attributes(self, nmap_output):
        """ Assign class attributes (properties) from the dictionary coming from the parsed XML.

            :param nmap_output:
            :type nmap_output: dict
        """
        self._start_timestamp = nmap_output['running_info']['start_timestamp']
        self._exit_status = nmap_output['running_info']['exit_status']
        self._start_time = nmap_output['running_info']['start_time']
        self._args = nmap_output['running_info']['args']
        self._summary = nmap_output['running_info']['summary']
        self._version = nmap_output['running_info']['version']
        self._end_time = nmap_output['running_info']['end_time']
        self._end_timestamp = nmap_output['running_info']['end_timestamp']
        self._scanned_protocols_info = nmap_output['scan_info']
        self._result = nmap_output['scan']

    def _has_finished(func):
        """ Raises NmapScanError if scanner has not finished or was not performed.

            :raises: NmapScanError
        """

        def check_finish_tag(self, *args, **kwargs):
            if not self.finished:
                raise NmapScanError('Scan was not completed or was not even launched.')
            return func(self, *args, **kwargs)

        return check_finish_tag

    @_has_finished
    def raw_data(self):
        """ Returns the parsed dictionary itself containing all the scan information.

            :return: Structured nested dictionary
            :rtype: dict
        """
        return self._result

    @_has_finished
    def scanned_hosts(self):
        """ Returns a list containing all scanned hosts.

            :return: List of scanned hosts
            :rtype: list
        """
        return [ip for ip in self._result]

    @_has_finished
    def non_scanned_hosts(self):
        """ Return a list of hosts that did not respond to the scan.

            :return: List of non scanned hosts
            :rtype: list
        """
        return [t for t in self._target_list if t not in self._result]

    @_has_finished
    def state(self, host):
        """ Return the state of a host. It returns None if the host was not scanned.

            :param host: Host where to get the state from.
            :type host: str
            :return: Host's state. None if the host does not exists
            :rtype: str, None
            :raises: NmapScanError if host does not exist.
        """
        try:
            return self._result[host]['state']
        except KeyError:
            raise NmapScanError('Host does not exist in the scan result.') from None

    @_has_finished
    def reason(self, host):
        """ Returns the reason why a host was successfully scanned. It returns None if the host was not scanned

            :param host: Host where to get the reason from.
            :type host: str
            :return: Reason from scan success. None if host does not exists.
            :rtype: str, None
            :raises: NmapScanError if host does not exist.
        """
        try:
            return self._result[host]['reason']
        except KeyError:
            raise NmapScanError('Host does not exist in the scan result.') from None

    @_has_finished
    def all_protocols(self, host):
        """ Yields all scanned protocols from a host.

            :param host: Host where to get the protocols from.
            :type host: str
            :return: Iterable with all scanned protocol
            :rtype: str
            :raises: NmapScanError if host does not exist.
        """
        try:
            for proto in self._result[host]['protocols']:
                yield proto
        except KeyError:
            raise NmapScanError('Host does not exist in the scan result.') from None

    @_has_finished
    def scanned_ports(self, host, protocol):
        """ Return a list of scanned ports for a given host and protocol.

            :param host: Host where to get the ports from.
            :param protocol: Protocol specification
            :type host: str
            :type protocol: str
            :return: List of scanned ports from a host and protocol
            :rtype: list
            :raises: NmapScanError if host or protocol do not exist.
        """
        try:
            return [int(p) for p in self._result[host]['protocols'][protocol]]
        except KeyError:
            raise NmapScanError('Host and/or protocol do not exist.') from None

    @_has_finished
    def non_scanned_ports(self, host, protocol):
        """ Return a list of non scanned ports for a given host and protocol.

                :param host: Host where to get the ports from.
                :param protocol: Protocol specification
                :type host: str
                :type protocol: str
                :return: List of non scanned ports from a host and protocol
                :rtype: list
                :raises: NmapScanError if host or protocol do not exist.
        """
        try:
            return [p for p in self._port_list if str(p)
                    not in self._result[host]['protocols'][protocol]]
        except KeyError:
            raise NmapScanError('Host and/or protocol do not exist.') from None

    @_has_finished
    def hostnames(self, host):
        """ Returns a list containing all hostnames from a given host, eliminating duplicates.

            :param host: Host where to get the hostnames from.
            :type host: str
            :return: List of hostnames,.
            :rtype: list
            :raises: NmapScanError if host does not exist.
        """
        try:
            return list(set(self._result[host]['hostnames']))
        except KeyError:
            raise NmapScanError('Host does not exist in the scan result.') from None

    @_has_finished
    def os_matches(self, host):
        """ Yield every OS name and accuracy for every OS match from a given host.

            :param host: Host where to get the os info from.
            :type host: str
            :return: OS name and accuracy for every os match
            :rtype: iter
            :raises: NmapScanError if host does not exist.
        """
        try:
            for os_dict in self._result[host]['os']['matches']:
                yield os_dict['name'], os_dict['accuracy']
        except KeyError:
            raise NmapScanError('Host does not exist in the scan result.') from None

    @_has_finished
    def os_fingerprint(self, host):
        """ Returns the OS fingerprint from a given host. If there is no fingerprint match or the host was not scanned,
        it will return None.

            :param host: Host where to get the os fingerprint from.
            :type host: str
            :return: OS fingerprint. None if there is no fingerprint or there is no such host
            :rtype: str, None
            :raises: NmapScanError if the host does not exist.
        """
        try:
            return self._result[host]['os']['fingerprint']
        except KeyError:
            raise NmapScanError('Host does not exist in the scan result.') from None

    @_has_finished
    def most_accurate_os(self, host):
        """ Returns a list of the most accurate OS matches for a given host. If there is no OS match or no OS match was
        performed, it will return None.

            :param host: Host where to get the most accurate OSes.
            :type host: str
            :return: List of most accurate OSes.
            :rtype: list
            :raises: NmapScanError if the host does not exist.
        """
        try:
            best_accuracy = self._result[host]['os']['matches'][0]['accuracy']
        except KeyError:
            raise NmapScanError('Host does not exist in the scan result.') from None

        return [o['name'] for o in self._result[host]['os']['matches']
                if o['accuracy'] == best_accuracy]

    @_has_finished
    def port_state(self, host, protocol, port):
        """ Yields the state and reason from a port, given a host and a protocol.

            :param host: Host where to get the port info from
            :param protocol: Protocol specification of the port.
            :param port: Target port
            :type host: str
            :type protocol: str
            :type port: str, int
            :return: state and reason
            :rtype: iter
                WHERE
                state str is the state of the port
                reason str is the reason for that port to be classified as open.
            :raises: NmapScanError if host, protocol or port do not exist.
        """
        try:
            port = self._result[host]['protocols'][protocol][str(port)]
            return port['state'], port['reason']
        except KeyError as e:
            if host in str(e):
                raise NmapScanError('Host does not exist in the scan result.') from None
            elif protocol in str(e):
                raise NmapScanError('Protocol does not exist for given host: {}'.format(host)) from None
            else:
                raise NmapScanError('Port doest no exist in scan result for given host and'
                                    'protocol: {} - {}'.format(host, protocol)) from None

    @_has_finished
    def service(self, host, protocol, port):
        """ Returns a Service instance containing the information from a service for
        a given host, protocol and port. None if no service information was found

            :param host: Host where to get the port info from
            :param protocol: Protocol specification of the port.
            :param port: Target port
            :type host: str
            :type protocol: str
            :type port: str, int
            :return: Service instance from that port.
            :rtype: Service
            :raises: NmapScanError if host, port or protocol do not exist.
        """

        try:
            return self._result[host]['protocols'][protocol][str(port)]['service']
        except KeyError as e:
            if host in str(e):
                raise NmapScanError('Host does not exist in the scan result.') from None
            elif protocol in str(e):
                raise NmapScanError('Protocol does not exist for given host: {}'.format(host)) from None
            else:
                raise NmapScanError('Port doest no exist in scan result for given host and'
                                    'protocol: {} - {}'.format(host, protocol)) from None

    @_has_finished
    def standard_service_info(self, host, protocol, port):
        """ Returns the service name and service detection info for a specific port. The name is just the
        service name, but the service detection info is a string containing the service product, version and extrainfo
        which it is the standard nmap output. In terms of this module, the service detection info is a string containing
        the service_instance.product, service_instance.version and service_instance.extrainfo

            :param host: Host where to get the port info from
            :param protocol: Protocol specification of the port
            :param port: Target port
            :type host: str
            :type protocol: str
            :type port: int, str
            :returns: tuple
                WHERE
                name is the service name, None if it does not exist.
                service_info is the service information standard output. None if it does not exist.
            :raises: NmapScanError if the host, protocol or port do no exist.
        """
        try:
            service_instance = self._result[host]['protocols'][protocol][str(port)]['service']
        except KeyError as e:
            if host in str(e):
                raise NmapScanError('Host does not exist in the scan result.') from None
            elif protocol in str(e):
                raise NmapScanError('Protocol does not exist for given host: {}'.format(host)) from None
            else:
                raise NmapScanError('Port doest no exist in scan result for given host and'
                                    'protocol: {} - {}'.format(host, protocol)) from None

        if service_instance is None:
            return None, None

        else:
            product = service_instance.product if service_instance.product is not None else ''
            version = service_instance.version if service_instance.version is not None else ''
            extrainfo = service_instance.extrainfo if service_instance.extrainfo is not None else ''
            service_detection_info = ' '.join([product, version, extrainfo]).strip()

            return service_instance.name, service_detection_info

    @_has_finished
    def port_script(self, host, protocol, port, script_name):
        """ Returns the script output for a given host, protocol, port.

            :param host: Host where to get the port info from
            :param protocol: Protocol specification of the port
            :param port: Target port
            :param script_name: Script name
            :type host: str
            :type protocol: str
            :type port: int, str
            :type script_name: str
            :returns: any
        """

        try:
            service_instance = self._result[host]['protocols'][protocol][str(port)]['service']
        except KeyError as e:
            if host in str(e):
                raise NmapScanError('Host does not exist in the scan result.') from None
            elif protocol in str(e):
                raise NmapScanError('Protocol does not exist for given host: {}'.format(host)) from None
            else:
                raise NmapScanError('Port doest no exist in scan result for given host and '
                                    'protocol: {} - {}'.format(host, protocol)) from None

        if service_instance is not None:
            for n, o in service_instance.all_scripts():
                if n == script_name:
                    return o
        raise NmapScanError('Host {}({}):{} does not have'
                            ' any information related to {}'.format(host, protocol, port, script_name)) from None

    @_has_finished
    def port_scripts(self, host, protocol, port, script_name=None):
        """ Yields all scripts names and output that where executed for a specific port.

            :param host: Host where to get the port info from
            :param protocol: Protocol specification of the port
            :param port: Target port
            :param script_name: Optional NSE script name
            :type host: str
            :type protocol: str
            :type port: int, str
            :type script_name: str
            :returns: iter
                WHERE
                name str is the script name
                output str is the script execution output.
        """
        try:
            service_instance = self._result[host]['protocols'][protocol][str(port)]['service']
        except KeyError as e:
            if host in str(e):
                raise NmapScanError('Host {} does not exist in the scan result.'.format(host)) from None
            elif protocol in str(e):
                raise NmapScanError('Protocol does not exist for given host: {}:{}'.format(host, protocol)) from None
            else:
                raise NmapScanError('Port {} doest no exist in scan result for given host and '
                                    'protocol: {} - {}'.format(port, host, protocol)) from None

        if service_instance is not None:

            scripts_list = service_instance.scripts.items() if script_name is None else \
                           [(x, y) for x, y in service_instance.scripts.items if script_name in x]

            for name, output in scripts_list:
                yield name, output

    @_has_finished
    def host_script(self, host, script_name):
        """ Yields every name and output for each script launched to the host.

            :param host: Host where to get the scripts info from
            :param script_name: NSE script name
            :type host: str
            :type script_name: str
            :returns: Script output
            :rtype: any
        """
        host_scripts = self._result[host]['scripts'] if script_name is None else \
                       [x for x in self._result[host]['scripts'] if script_name in x['name']]
        for script in host_scripts:
            if script['name'] == script_name:
                return script['output']
        raise NmapScanError('Host {} does not have'
                            ' any information related to {}'.format(host, script_name)) from None

    @_has_finished
    def host_scripts(self, host, script_name=None):
        """ Yields every name and output for each script launched to the host.

            :param host: Host where to get the scripts info from
            :param script_name: Optional NSE script name
            :type host: str
            :type script_name: str
            :returns: tuple
                WHERE
                name str is the script name
                output str, None is the script execution result
        """
        host_scripts = self._result[host]['scripts'] if script_name is None else \
            [x for x in self._result[host]['scripts'] if script_name in x['name']]
        for script in host_scripts:
            yield script['name'], script['output']

    @_has_finished
    def trace_info(self, host):
        """ Yields every TraceHop instances representing the hops form a traceroute execution.

            :param host: Host where to get the traceroute info from
            :type host: str
            :returns: TraceHop instance
            :rtype; TraceHop
        """

        for trace_instance in self._result[host]['trace']:
            yield trace_instance

    @_has_finished
    def merge(self, *args, **kwargs):
        """ Merge the current NmapScan instance with the other provided instances

            :param args: Any number of NmapScanner instances
            :type args: NmapScanner
        """

        merge_tcp = kwargs.get('merge_tcp', True)
        merge_udp = kwargs.get('merge_udp', True)
        merge_scripts = kwargs.get('merge_scripts', True)
        merge_trace = kwargs.get('merge_trace', True)
        merge_os = kwargs.get('merge_os', True)
        merge_non_scanned = kwargs.get('merge_non_scanned', False)

        # Raise exception if no args
        if not len(args):
            raise NmapScanError('NmapScanner.merge() method requires at least one argument')

        # All args must be NmapScanner instances
        if not all([isinstance(x, NmapScanner) for x in args]):
            raise NmapScanError('Cannot merge non NmapScanner objects')

        # Loop through each scanner
        for current_scanner in args:
            # Check each single host from the scanner
            for host in current_scanner.scanned_hosts():
                # Check if host is stored on the current instance.
                # If the host does not exist on the current instance, copy the dictionary section
                # depending on the merge_tcp and merge_udp values
                if host not in self._result:
                    self._result[host] = {'protocols': []}
                    self._target_list.append(host)
                    current_raw_data = current_scanner.raw_data()
                    if merge_tcp and 'tcp' in current_raw_data[host]['protocols']:
                        self._result[host]['protocols']['tcp'] = current_raw_data[host]['protocols']['tcp']
                    if merge_udp and 'udp' in current_raw_data[host]['protocols']:
                        self._result[host]['protocols']['udp'] = current_raw_data[host]['protocols']['udp']
                    if merge_trace:
                        self._result[host]['trace'] = current_raw_data[host]['trace']
                    if merge_os:
                        self._result[host]['os'] = current_raw_data[host]['os']
                    if merge_scripts:
                        self._result[host]['scripts'] = current_raw_data[host]['scripts']
                    if merge_non_scanned:
                        # Append non scanned by just appending those targets from the target list that are not
                        # already in the current list
                        for i in current_scanner._target_list:
                            if i not in self._target_list:
                                self._target_list.append(i)
                # If host already in scanner
                else:
                    current_raw_data = current_scanner.raw_data()
                    # If the current instance does not have TCP for the current target, add the information
                    # from the current scan. If the instance on the other hand has information for that particular
                    # protocol, add the ports that have not been scanned within the instance nmap scan.
                    # Do the same for UDP.
                    # Note: This includes services and port scripts
                    if merge_tcp and 'tcp' not in self._result[host]['protocols'] and \
                            'tcp' in current_raw_data[host]['protocols']:
                        self._result[host]['protocols']['tcp'] = current_raw_data[host]['protocols']['tcp']
                    elif merge_tcp and 'tcp' in self._result[host]['protocols'] and \
                            'tcp' in current_raw_data[host]['protocols']:
                        for port in current_raw_data[host]['protocols']['tcp']:
                            if port not in self._result[host]['protocols']['tcp']:
                                self._result[host]['protocols']['tcp'][port] = \
                                    current_raw_data[host]['protocols']['tcp'][port]

                    if merge_udp and 'udp' not in self._result[host]['protocols'] and \
                            'udp' in current_raw_data[host]['protocols']:
                        self._result[host]['protocols']['udp'] = current_raw_data[host]['protocols']['udp']
                    elif merge_udp and 'udp' in self._result[host]['protocols'] and \
                            'udp' in current_raw_data[host]['protocols']:
                        for port in current_raw_data[host]['protocols']['udp']:
                            if port not in self._result[host]['protocols']['udp']:
                                self._result[host]['protocols']['udp'][port] = \
                                    current_raw_data[host]['protocols']['udp'][port]

                    # Keep checking the rest of the host attributes
                    # Only add Traceroute information if there is not info (Merging that information may
                    # be problematic)
                    if merge_trace:
                        if not len(self._result[host]['trace']):
                            self._result[host]['trace'] = current_raw_data[host]['trace']
                    if merge_os:
                        if not len(self._result[host]['os']['matches']):
                            try:
                                self._result[host]['os']['matches'] = current_raw_data[host]['os']['matches']
                            except KeyError:
                                pass
                        else:
                            try:
                                for i in current_raw_data[host]['os']['matches']:
                                    if i not in self._result[host]['os']['matches']:
                                        self._result[host]['os']['matches'].append(i)
                            except KeyError:
                                pass
                    if merge_scripts:
                        for i in current_raw_data[host]['scripts']:
                            if i not in self._result[host]['scripts']:
                                self._result[host]['scripts'].append(i)
                    if merge_non_scanned:
                        # Append non scanned by just appending those targets from the target list that are not
                        # already in the current list
                        for i in current_scanner._target_list:
                            if i not in self._target_list:
                                self._target_list.append(i)


class AsyncNmapScanner(NmapScanner):

    def __init__(self, target, **kwargs):
        NmapScanner.__init__(self, target, **kwargs)
        self._mute_error = kwargs.get('mute_error', False)
        self._wrapper = kwargs.get('wrapper', threading.Thread)
        self._running = False
        self._had_fatal_errors = False
        self._exception_stack = []
        self._execution_thread = None

        self._assert_attributes()

    def _assert_attributes(self):
        """ Asserts additional attributes."""
        assert isinstance(self._mute_error, bool)

    def _background_run(self):
        """ Runs the nmap command as a terminal process, redirect all the output and errors to variables. Then tries to
        parse the output. If output could not be parsed due to malformed XML then raise a NmapScanError.
        If output could be parsed but there are still errors, save them into de self.tolerant_errors property. After
        that, assign instance attributes and set finished to True.

            :raises: NmapScanError

        note::
            This 'copy-paste' method from the super class is needed, because it was a few changes, because
            depending on the class attributes on instantiation (kwargs), Exceptions raised might be
            treated in a different way
        """

        self._running = True

        if self.targets is None or not len(self.targets):
            if self._mute_error:
                self._exception_stack.append(NmapScanError('You must specify targets to scan.'))
                self._had_fatal_errors = True
                self._running = False
                self._finished = True
                return
            else:
                self._finished = True
                self._running = False
                raise NmapScanError('You must specify targets to scan.')

        parsed_nmap_output = None

        # Add the XML output format, build the hole nmap command.
        to_execute = ['nmap', '-oX', '-'] + self.scan_arguments
        # If ports specified, add them as -p parameter, in other case ports will be automatically chosen
        if self.ports is not None:
            to_execute.append('-p' + self.ports)
        # Add the targets
        to_execute.append(self.targets)

        # Call and block a subprocess, then redirect output and errors to a variable each.
        nmap_process = subprocess.Popen(to_execute, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = nmap_process.communicate()
        # If there is output
        if len(output):
            try:
                parsed_nmap_output = _XMLParser(output.decode('utf8')).parse()
            # If parsing error raise NmapScanError with STDERR info.
            except ET.ParseError:
                if self._mute_error:
                    self._exception_stack.append(NmapScanError('Could not parse output from nmap. STDERR says:\n{}'.format(error.decode('utf8'))))
                    self._had_fatal_errors = True
                    self._running = False
                    self._finished = True
                    return
                else:
                    self._running = False
                    self._finished = True
                    raise NmapScanError('Could not parse output from nmap. STDERR says:\n{}'.format(error.decode('utf8')))

        # If there is no output, raise NmapScanError with STDERR info
        else:
            if self._mute_error:
                self._exception_stack.append(NmapScanError('Could not parse output from nmap. STDERR says:\n{}'.format(error.decode('utf8'))))
                self._had_fatal_errors = True
                self._running = False
                self._finished = True
            else:
                self._running = False
                self._finished = True
                raise NmapScanError('No output from process was given. STDERR says:\n{}'.format(error.decode('utf8')))

        # If any error but method reaches this point, there are tolerant errors.
        if len(error):
            self._tolerant_errors = error

        # Assign class attributes from the parsed information.
        self._assign_class_attributes(parsed_nmap_output)

        # Execute all the functions that were registered in the engine
        if self.engine is not None:
            self._execute_engine_scripts()

        # Set finished variable to True
        self._finished = True
        self._running = False

    def fatal_errors(self):
        """ Returns the Exception stack from the programmed scan.

        :return: List of exceptions
        :rtype: list
        """
        return self._exception_stack

    def is_running(self):
        """ Tells if the scan is currently running.

            :return: True if the scan is running, False if not.
            :rtype: bool
        """
        return self._running

    def wait(self):
        """ Blocks the execution and waits for the Thread to finish.
        """
        self._execution_thread.join()

    def finished_successfully(self):
        """ Return True if the Scan has finished with no fatal erros. False if not

            :return: True if finished, False if not
            :rtype: bool
        """

        return self.finished and not self._had_fatal_errors

    def run(self):
        """ Creates a Thread and executes the __background_run() method, which is the normal NmapScanner.run()
        but with some variations adapted to the Async class attributes.
        """
        self._execution_thread = self._wrapper(target=self._background_run, args=[])
        self._execution_thread.start()

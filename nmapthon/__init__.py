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

import re
import socket
import struct
import subprocess
import threading
import xml.etree.ElementTree as ET


#######################################
# Exception Classes
#######################################


class InvalidPortError(Exception):
    """ Exception class for port assignment and parsing errors.
    """

    def __init__(self, message):
        Exception.__init__(self, message)


class MalformedIpAddressError(Exception):
    """ Exception class for target assignment and parsing errors.
    """

    def __init__(self, message):
        Exception.__init__(self, message)


class InvalidArgumentError(Exception):
    """ Exception class for nmap arguments assignment and parsing errors.
    """

    def __init__(self, message):
        Exception.__init__(self, message)


class XMLParsingError(Exception):
    """ Exception class for nmap output parsing errors.
    """

    def __init__(self, message):
        Exception.__init__(self, message)


class NmapScanError(Exception):
    """ Exception class for nmap scanning errors.
    """

    def __init__(self, message):
        Exception.__init__(self, message)


#######################################
# Module Classes
#######################################


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
                raise XMLParsingError('Could not parse host\'s IP address.')

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
        assert isinstance(name, str) and isinstance(output, str)

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

    def __str__(self):
        """ Instance string formatting

            :return: String representation of the class
            :rtype: str
        """
        # If all class attributes are None, return 'None existing service'
        if self.name is None and self.product is None and self.version is None and \
                self.extrainfo is None and not len([cpe for cpe in self.all_cpes()]) and \
                not len({name: output for name, output in self.all_scripts()}):
            return 'None existing service'

        base_string = "Name: "
        if self.name is not None:
            base_string += self.name + '\r\n'
        else:
            base_string += 'Unknown\r\n'
        base_string += "Product: "
        if self.product is not None:
            base_string += self.product + '\r\n'
        else:
            base_string += 'Unknown\r\n'
        base_string += "Version: "
        if self.version is not None:
            base_string += self.version + '\r\n'
        else:
            base_string += 'Unknown\r\n'
        base_string += "Extra info: "
        if self.extrainfo is not None:
            base_string += self.extrainfo + '\r\n'
        else:
            base_string += 'Unknown\r\n'
        for cpe in self.all_cpes():
            base_string += "CPE: " + cpe + '\r\n'
        for name, output in self.all_scripts():
            base_string += "SCRIPT:" + '\r\n'
            base_string += "NAME:" + name + '\r\n'
            base_string += "OUTPUT:" + output + '\r\n'

        return base_string


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

    def __str__(self):
        """ String formatting of a TraceHop instance. If all attributes are None, it returns 'Somehow blocked Hop',
         in any other case, prints his attributes information if they are not None, and 'Unknown' if they are.

            :return: String containing instance information
            :rtype: str
        """
        base_string = ''
        if self.ttl is None and self.ip_addr is None and self.rtt is None and self.domain_name is None:
            base_string += 'Somehow blocked Hop.'
        else:
            base_string += 'TTL: '
            if self.ttl is not None:
                base_string += str(self.ttl + '\r\n')
            else:
                base_string += 'Unknown\r\n'
            base_string += 'IP Address: '
            if self.ip_addr is not None:
                base_string += self.ip_addr + '\r\n'
            else:
                base_string += 'Unknown\r\n'
            base_string += 'RTT: '
            if self.rtt is not None:
                base_string += str(self.rtt + '\r\n')
            else:
                base_string += 'Unknown\r\n'
            base_string += 'Domain name: '
            if self.domain_name is not None:
                base_string += self.domain_name + '\r\n'
            else:
                base_string += 'Unknown\r\n'

        return base_string


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
        targets: List of targets or string containing them.
        ports: List of ports or string containing them.
        arguments: List of arguments or string containing them.
    """

    def __init__(self, targets, **kwargs):
        self.name = kwargs.get('name')
        self.targets = targets
        self.ports = kwargs.get('ports')
        self.scan_arguments = kwargs.get('arguments')
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
            self._target_list = self.__parse_targets(targets)
            self._targets = targets
        elif isinstance(targets, list):
            for i in targets:
                if not self.__is_ip_address(i):
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
            self._port_list = self.__parse_ports_from_str(ports)
            self._ports = ports
        elif isinstance(ports, list):
            self._ports = self.__parse_ports_from_list(ports)
            self._port_list = ports
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
            self._scan_arguments = arguments

        elif isinstance(arguments, str):
            self._scan_arguments = self.__parse_arguments(arguments)

        elif isinstance(arguments, list):
            self._scan_arguments = arguments

        else:
            raise InvalidArgumentError('Scanner arguments must be a string or a list of arguments.')

        assert isinstance(self.scan_arguments, list) or arguments is None

    def __is_valid_port(self, port):
        """Checks if a given value might be an existing port. Must be between 1 and 65535, both included.

            :param port: Port candidate
            :type port: int, str
            :return: True if is valid, False if not
            :rtype: bool
        """
        try:
            int_port = int(port)
        except ValueError:
            return False

        return 0 < int_port < 65536

    def __parse_ports_from_str(self, ports):
        """ Returns a list containing all ports specified in an nmap-format port string.

            :param ports: String that specifies the ports to scan
            :type ports: str
            :return: List containing the ports to scan as Strings.
            :rtype: list
            :raises: InvalidPortError

        Example:
            ports               return
            '10,20,30'          ['10', '20', '30']
            '10-13'             ['10'. '11', '12', '13']
            '80, 81-83'         ['80', '81', '82', '83']
        """
        # Create empty list and delete any blank spaces
        port_list = []
        # Delete blank spaces
        ports_string = ports.replace(' ', '')

        # For every comma separated block
        for split_ports in ports_string.split(','):
            # If there is a range indicator.
            if '-' in split_ports:
                # Split the range
                port_range = split_ports.split('-')
                # Cast to integer the starting port range number.
                try:
                    first_port_range = int(port_range[0])
                # If ValueError, non valid port, format the InvalidPortError message.
                except ValueError:
                    first_port = port_range[0] if len(port_range[0]) else 'None'
                    raise InvalidPortError('Invalid starting port range: {}'.format(first_port))
                # Cast ending port range
                try:
                    last_port_range = int(port_range[1]) + 1
                # If IndexError, no ending port range was specified.
                except IndexError:
                    raise InvalidPortError('End of port range in {}- not specified'.format(port_range[0]))
                # If ValueError, invalid ending for port range.
                except ValueError:
                    raise InvalidPortError('Invalid ending port range: {} '.format(port_range[1]))
                # For every port in the range calculated
                for single_port in range(first_port_range, last_port_range):
                    # If valid port, add to list
                    if self.__is_valid_port(single_port):
                        port_list.append(single_port)
                    # If invalid, raise Exception
                    else:
                        raise InvalidPortError('{} is not a correct port'.format(single_port))
            # If no range indicators, guess individual port
            else:
                # If split port has length
                if len(split_ports):
                    # Cast to integer value
                    try:
                        integer_parsed_port = int(split_ports)
                    # If ValueError, malformed
                    except ValueError:
                        raise InvalidPortError('Invalid port: {}'.format(split_ports))
                    # If is a valid port, append it to list
                    if self.__is_valid_port(integer_parsed_port):
                        port_list.append(integer_parsed_port)
                    # If invalid, raise Error
                    else:
                        raise InvalidPortError('{} is not a correct port.'.format(integer_parsed_port))

        return sorted(list(set(port_list)))

    def __parse_ports_from_list(self, port_list):
        """ Parse a list of int/str ports into a single str containing a port range that nmap can understand.

            :param port_list: List of ports
            :type port_list: list
            :return: String representing the ports in nmap syntax
            :rtype: str
        """

        # Try integer conversion, if ValueError raise NmapScanError
        try:
            int_port_list = map(int, port_list)
        except ValueError:
            raise NmapScanError('Port list must be filled with int or str type ports.')

        # If not all ports are valid ports, raise NmapScanError
        if not all(self.__is_valid_port(p) for p in int_port_list):
            raise NmapScanError('Ports must be between 0 and 65536')

        # Sort ports in ascending order
        sorted_ports = sorted(int_port_list)
        # Instanciate port string
        port_string = ''
        # Instantiate last port variable
        last_port = -2
        # Loop through sorted_ports list, bust access the ports by position.
        # Used to know when the list is about to finish
        i = 0
        while i < len(sorted_ports):
            # If the current port is not the immediate next one
            if sorted_ports[i] != (last_port + 1):
                port_string += str(sorted_ports[i])
                # Set last_port to current port
                last_port = sorted_ports[i]
                # Append a comma if the port is not the last one
                if i != (len(sorted_ports) - 1) and sorted_ports[i + 1] != (sorted_ports[i] + 1):
                    port_string += ','
                # Add one to i
                i += 1
            # If the current port is the previous port plus 1
            else:
                # Add a dash (range indicator)
                port_string += '-'
                # Set last_port to current port
                last_port = sorted_ports[i]
                # Add one to i
                i += 1
                # keep going if next ports are immediate next
                while i < len(sorted_ports) and sorted_ports[i] == (last_port + 1):
                    last_port = sorted_ports[i]
                    i += 1
                # On exit of while loop, range ends, write last port range
                port_string += str(last_port)
                # Append a comma if the port is not the last one
                if i != len(sorted_ports):
                    port_string += ','

        return port_string

    def __is_ip_address(self, ip_address):
        """Checks if a given IP address is correctly formed.

            :param ip_address: IP address to check
            :type ip_address: str
            :return: True if it is a valid IP Address, False if not
            :rtype: bool
        """
        # IP address regex
        ip_address_regex = re.compile('^(([0-9]|[1-9][0-9]|1[0-9]{2}|'
                                      '2[0-4][0-9]|25[0-5])\.){3}([0-9]|'
                                      '[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$')

        # Return True if matches, False if not.
        return ip_address_regex.match(ip_address)

    def __ip_range(self, starting_ip, ending_ip):
        """ Calculates a list of IPs between two given.

            :param starting_ip: Range starting IP address
            :param ending_ip: Range ending IP address
            :type starting_ip: str
            :type ending_ip: str
            :return: list
            """

        # Create a list contaning the 4 octets from both IP address in decimal format.
        split_starting_ip = list(map(int, starting_ip.split('.')))
        split_ending_ip = list(map(int, ending_ip.split('.')))
        # Create list of IPs to return, starting with the first one.
        ip_range = [starting_ip]

        # Execute algorithm. While you can add one to the most on the right octet, keep going
        # and add. If the 4 octets are named from 3 to 0 from left to right: when octet N is 255,
        # set octet N to 0 and add one to octet N+1
        while split_starting_ip != split_ending_ip:
            split_starting_ip[3] += 1
            for i in [3, 2, 1]:
                if split_starting_ip[i] == 256:
                    split_starting_ip[i] = 0
                    split_starting_ip[i - 1] += 1
            # Reformat to IP address-like string.
            current_ip = '.'.join(map(str, split_starting_ip))
            ip_range.append(current_ip)

        return ip_range

    def __dispatch_network(self, network):
        """ Creates a list of all the IP address inside a network with it's netmask in CIDR format.

            :param network: Netowrk IP address and /netmask to dispatch
            :type network: str
            :return: List of every IP on a network range
            :rtype: list
            :raises: MalformedIPAddressError
        """

        # List to return
        ip_addresses = []

        # Delete blank spaces and split IP Address and netmask in CIDR format.
        ip_address_netmask = network.replace(' ', '').split('/')
        # If not split in two parts, raise Exception.
        if len(ip_address_netmask) != 2:
            raise MalformedIpAddressError('Invalid network to dispatch: {}.'
                                          ' Need an IP address and CIDR Mask like 192.168.1.0/24'
                                          .format(ip_address_netmask))

        # IP Address is the first part
        ip_address = ip_address_netmask[0]

        # CIDR is the second part
        try:
            cidr = int(ip_address_netmask[1])
        # If cannot convert to integer, raise Exception
        except ValueError:
            raise MalformedIpAddressError('Invalid CIDR format: {}'.format(ip_address_netmask[1]))

        # If netmask not between 0 and 32, included, raise Exception
        if not 0 <= cidr <= 32:
            raise MalformedIpAddressError('Out of range CIDR: {}'.format(cidr))

        # If invalid IP address, raise Exception
        if not self.__is_ip_address(ip_address):
            raise MalformedIpAddressError('Invalid network IP: {}.'.format(ip_address))

        # Combination from struct and socket for binary formatting and bit level operations.
        # Getting every IP address inside a network range (established by netmask).
        host_bits = 32 - cidr
        aux = struct.unpack('>I', socket.inet_aton(ip_address))[0]
        start = (aux >> host_bits) << host_bits
        end = start | ((1 << host_bits) - 1)

        for ip in range(start, end):
            ip_addresses.append(socket.inet_ntoa(struct.pack('>I', ip)))

        # Return every IP address but not Network Address
        return ip_addresses[1:]

    def __parse_targets(self, targets):
        """ Returns a list containing all targets specified for the scan.

            :param targets: String that specifies the targets to scan
            :type targets: str
            :return: List containing the targets to scan as Strings.
            :rtype: list
            :raises: MalformedIPAddressError

        Example:
            targets                             return
            '192.168.1.1, 192.168.1.2'          ['192.168.1.1', '192.168.1.2']
            '192.168.1.1-192.168.1.3'           ['192.168.1.1', '192.168.1.2', '192.168.1.3']
            '192.168.1.0/30'                    ['192.168.1.1', '192.168.1.2']

        note:
            If network/cidr mask is specified, both Network address and broadcast address will be omitted.
        """

        # List to return
        target_list = []
        # Delete blank spaces
        targets_string = targets.replace(' ', '')

        # For each block split by a comma.
        for split_target in targets_string.split(','):
            # If range indicator
            if '-' in split_target:
                # Split range
                ip_range = split_target.split('-')
                # Get starting IP address from range
                starting_ip = ip_range[0]
                # If not a valid IP address, raise Error
                if not self.__is_ip_address(starting_ip):
                    raise MalformedIpAddressError('Invalid starting IP range: {}'.format(starting_ip))
                # Get Ending IP address from range
                ending_ip = ip_range[1]
                # If not valid IP address, raise Error
                if not self.__is_ip_address(ending_ip):
                    raise MalformedIpAddressError('Invalid ending IP range: {}'.format(ending_ip))
                # For every IP in range, add to list if valid IP. If not, raise Exception.
                for single_target_in_range in self.__ip_range(starting_ip, ending_ip):
                    if self.__is_ip_address(single_target_in_range):
                        target_list.append(single_target_in_range)
                    else:
                        raise MalformedIpAddressError('Invalid IP Address: {}'.format(single_target_in_range))
            # If a slash is found, guess a network mask
            elif '/' in split_target:
                # Extend the list for dispatching the network
                target_list.extend(self.__dispatch_network(split_target))
            # If it reaches here, guess single IP. Add to list or raise Error if malformed.
            else:
                if self.__is_ip_address(split_target):
                    target_list.append(split_target)
                else:
                    raise MalformedIpAddressError('Invalid IP Address: {}'.format(split_target))

        # Return the sorted list. List is sorted by IP address. Ej: 192.168.1.12 > 192.168.1.9
        return sorted(list(set(target_list)),
                      key=lambda ip: int(''.join(["%02X" % int(i) for i in ip.split('.')]), 16))

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
        if '-p' in arguments_string:
            raise InvalidArgumentError('Ports must be specified on instance creation or by instance.ports setter.')

        if '-v' in arguments_string:
            raise InvalidArgumentError('Scanner does not support verbosity parameter.')

        if '-d' in arguments_string:
            raise InvalidArgumentError('Scanner does not support debugging parameter.')

        # Split arguments with whitespaces
        arguments_list = arguments_string.split()
        # Check if there is an IP address on the arguments, if so, raise InvalidArgumentError
        if not all(not self.__is_ip_address(p) for p in arguments_list):
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
            try:
                parsed_nmap_output = _XMLParser(output).parse()
            # If parsing error raise NmapScanError with STDERR info.
            except (ET.ParseError, AttributeError) as e:
                raise NmapScanError('Could not parse output from nmap. STDERR says:\n{}'.format(e))

        # If there is no output, raise NmapScanError with STDERR info
        else:
            raise NmapScanError('No output from process was given. STDERR says:\n{}'.format(error.decode('utf8')))

        # If any error but method reaches this point, there are tolerant errors.
        if len(error):
            self._tolerant_errors = error

        # Assign class attributes from the parsed information.
        self._assign_class_attributes(parsed_nmap_output)
        # Set finished variable to True
        self._finished = True

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

    def has_finished(func):
        """ Raises NmapScannerError if scanner has not finished or was not performed.

            :raises: NmapScanError
        """

        def check_finish_tag(self, *args, **kwargs):
            if not self.finished:
                raise NmapScanError('Scan was not completed or was not even launched.')
            return func(self, *args, **kwargs)

        return check_finish_tag

    @has_finished
    def raw_data(self):
        """ Returns the parsed dictionary itself containing all the scan information.

            :return: Structured nested dictionary
            :rtype: dict
        """
        return self._result

    @has_finished
    def scanned_hosts(self):
        """ Returns a list containing all scanned hosts.

            :return: List of scanned hosts
            :rtype: list
        """
        return [ip for ip in self._result]

    @has_finished
    def non_scanned_hosts(self):
        """ Return a list of hosts that did not respond to the scan.

            :return: List of non scanned hosts
            :rtype: list
        """
        return [t for t in self._target_list if t not in self._result]

    @has_finished
    def state(self, host):
        """ Return the state of a host. It returns None if the host was not scanned.

            :param host: Host where to get the state from.
            :type host: str
            :return: Host's state. None if the host does not exists
            :rtype: str, None
            :raises: NmapScannerError if host does not exist.
        """
        try:
            return self._result[host]['state']
        except KeyError:
            raise NmapScanError('Host does not exist in the scan result.')

    @has_finished
    def reason(self, host):
        """ Returns the reason why a host was successfully scanned. It returns None if the host was not scanned

            :param host: Host where to get the reason from.
            :type host: str
            :return: Reason from scan success. None if host does not exists.
            :rtype: str, None
            :raises: NmapScannerError if host does not exist.
        """
        try:
            return self._result[host]['reason']
        except KeyError:
            raise NmapScanError('Host does not exist in the scan result.')

    @has_finished
    def all_protocols(self, host):
        """ Yields all scanned protocols from a host.

            :param host: Host where to get the protocols from.
            :type host: str
            :return: Iterable with all scanned protocol
            :rtype: str
            :raises: NmapScannerError if host does not exist.
        """
        try:
            for proto in self._result[host]['protocols']:
                yield proto
        except KeyError:
            raise NmapScanError('Host does not exist in the scan result.')

    @has_finished
    def scanned_ports(self, host, protocol):
        """ Return a list of scanned ports for a given host and protocol.

            :param host: Host where to get the ports from.
            :param protocol: Protocol specification
            :type host: str
            :type protocol: str
            :return: List of scanned ports from a host and protocol
            :rtype: list
            :raises: NmapScannerError if host or protocol do not exist.
        """
        try:
            return [int(p) for p in self._result[host]['protocols'][protocol]]
        except KeyError:
            raise NmapScanError('Host and/or protocol do not exist.')

    @has_finished
    def non_scanned_ports(self, host, protocol):
        """ Return a list of non scanned ports for a given host and protocol.

                :param host: Host where to get the ports from.
                :param protocol: Protocol specification
                :type host: str
                :type protocol: str
                :return: List of non scanned ports from a host and protocol
                :rtype: list
                :raises: NmapScannerError if host or protocol do not exist.
        """
        try:
            return [p for p in self._port_list if str(p)
                    not in self._result[host]['protocols'][protocol]]
        except KeyError:
            raise NmapScanError('Host and/or protocol do not exist.')

    @has_finished
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
            raise NmapScanError('Host does not exist in the scan result.')

    @has_finished
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
            raise NmapScanError('Host does not exist in the scan result.')

    @has_finished
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
            raise NmapScanError('Host does not exist in the scan result.')

    @has_finished
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
            raise NmapScanError('Host does not exist in the scan result.')

        return [o['name'] for o in self._result[host]['os']['matches']
                if o['accuracy'] == best_accuracy]

    @has_finished
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
            if host in e:
                raise NmapScanError('Host does not exist in the scan result.')
            elif protocol in e:
                raise NmapScanError('Protocol does not exist for given host: {}'.format(host))
            else:
                raise NmapScanError('Port doest no exist in scan result for given host and'
                                    'protocol: {} - {}'.format(host, protocol))

    @has_finished
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
            if host in e:
                raise NmapScanError('Host does not exist in the scan result.')
            elif protocol in e:
                raise NmapScanError('Protocol does not exist for given host: {}'.format(host))
            else:
                raise NmapScanError('Port doest no exist in scan result for given host and'
                                    'protocol: {} - {}'.format(host, protocol))

    @has_finished
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
            if host in e:
                raise NmapScanError('Host does not exist in the scan result.')
            elif protocol in e:
                raise NmapScanError('Protocol does not exist for given host: {}'.format(host))
            else:
                raise NmapScanError('Port doest no exist in scan result for given host and'
                                    'protocol: {} - {}'.format(host, protocol))

        if service_instance is None:
            return None, None

        else:
            product = service_instance.product if service_instance.product is not None else ''
            version = service_instance.version if service_instance.version is not None else ''
            extrainfo = service_instance.extrainfo if service_instance.extrainfo is not None else ''
            service_detection_info = ' '.join([product, version, extrainfo]).strip()

            return service_instance.name, service_detection_info

    # TODO: Add to docs
    @has_finished
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
            if host in e:
                raise NmapScanError('Host does not exist in the scan result.')
            elif protocol in e:
                raise NmapScanError('Protocol does not exist for given host: {}'.format(host))
            else:
                raise NmapScanError('Port doest no exist in scan result for given host and'
                                    'protocol: {} - {}'.format(host, protocol))

        scripts_list = service_instance.scripts.items() if script_name is None else \
            [(x, y) for x, y in service_instance.scripts.items if script_name in x]

        if service_instance is not None:
            for name, output in scripts_list:
                yield name, output

    @has_finished
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

    @has_finished
    def trace_info(self, host):
        """ Yields every TraceHop instances representing the hops form a traceroute execution.

            :param host: Host where to get the traceroute info from
            :type host: str
            :returns: TraceHop instance
            :rtype; TraceHop
        """

        for trace_instance in self._result[host]['trace']:
            yield trace_instance

    @has_finished
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
            raise NmapScanError('merge() method requires at least one element')

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

    def __init__(self, **kwargs):
        NmapScanner.__init__(self, **kwargs)
        self.__mute_error = kwargs.get('mute_error') if kwargs.get('mute_error') is not None else False
        self.__running = False
        self.__had_fatal_errors = False
        self.__exception_stack = []
        self.__execution_thread = None

        self.__assert_attributes()

    def __assert_attributes(self):
        """ Asserts aditional attributes."""
        assert isinstance(self.__mute_error, bool)

    def __background_run(self):
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

        self.__running = True

        if self.targets is None or not len(self.targets):
            if self.__mute_error:
                self.__exception_stack.append(NmapScanError('You must specify targets to scan.'))
                self.__had_fatal_errors = True
                self.__running = False
                self._finished = True
                return
            else:
                self._finished = True
                self.__running = False
                raise NmapScanError('You must specify targets to scan.')

        parsed_nmap_output = None

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
            try:
                parsed_nmap_output = _XMLParser(str(output)).parse()

            # If parsing error raise NmapScanError with STDERR info.
            except ET.ParseError:
                if self.__mute_error:
                    self.__exception_stack.append(NmapScanError('Could not parse output from nmap. STDERR says:\r\n'
                                                                + error))
                    self.__had_fatal_errors = True
                    self.__running = False
                    self._finished = True
                    return
                else:
                    self.__running = False
                    self._finished = True
                    raise NmapScanError('Could not parse output from nmap. STDERR says:\r\n' + error)

        # If there is no output, raise NmapScanError with STDERR info
        else:
            if self.__mute_error:
                self.__exception_stack.append(NmapScanError('Could not parse output from nmap. STDERR says:\r\n'
                                                            + error))
                self.__had_fatal_errors = True
                self.__running = False
                self._finished = True
            else:
                self.__running = False
                self._finished = True
                raise NmapScanError('No output from process was given. STDERR says:\r\n' + error)

        # If any error but method reaches this point, there are tolerant errors.
        if len(error):
            self.__tolerant_errors = error

        # Assign class attributes from the parsed information.
        NmapScanner._assign_class_attributes(self, parsed_nmap_output)

        # Set finished variable to True
        self._finished = True
        self.__running = False

    def fatal_errors(self):
        """ Returns the Exception stack from the programmed scan.

        :return: List of exceptions
        :rtype: list
        """
        return self.__exception_stack

    def is_running(self):
        """ Tells if the scan is currently running.

            :return: True if the scan is running, False if not.
            :rtype: bool
        """
        return self.__running

    def wait(self):
        """ Blocks the execution and waits for the Thread to finish.
        """
        self.__execution_thread.join()

    def finished_successfully(self):
        """ Return True if the Scan has finished with no fatal erros. False if not

            :return: True if finished, False if not
            :rtype: bool
        """

        return self.finished and not self.__had_fatal_errors

    def run(self):
        """ Creates a Thread and executes the __background_run() method, which is the normal NmapScanner.run()
        but with some variations adapted to the Async class attributes.
        """
        self.__execution_thread = threading.Thread(target=self.__background_run, args=[])
        self.__execution_thread.start()

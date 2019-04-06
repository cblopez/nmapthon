#!/usr/bin/env python

"""

Python module to provide nmap scanning for any Python project.

This module uses Systems calls to execute the nmap tool, which has to be installed on the system using this library.
All the classes provided here have their own functionality and use cases. With nmapthon.py a user will be able to:
- Perform any nmap scan.
- Get any peace of the scan information just using a method.
- Perform multiprocessing scans.
- Perform asynchronous scans.
- Customize scans names.
- Keep track of all scans history.

This library also contains every tool needed to parse all the information provided by the user, a large set of
custom Exceptions to reflect any type of error the scan could have, printing a clear message to the user about why
the error occurred.
"""
from __future__ import print_function

import re
import socket
import sys
import struct
import subprocess
import threading
import time
import xml.etree.ElementTree as ET


#######################################
# Exception Classes
#######################################


class InvalidPortError(Exception):

    def __init__(self, message):
        Exception.__init__(self, message)


class MalformedIpAddressError(Exception):

    def __init__(self, message):
        Exception.__init__(self, message)


class InvalidArgumentError(Exception):

    def __init__(self, message):
        Exception.__init__(self, message)


class XMLParsingError(Exception):

    def __init__(self, message):
        Exception.__init__(self, message)


class NmapScanError(Exception):

    def __init__(self, message):
        Exception.__init__(self, message)


class ScanQueueError(Exception):

    def __init__(self, message):
        Exception.__init__(self, message)


#######################################
# Module Classes
#######################################


class _XMLParser:
    """ XML parser that takes an nmap scan output and parsers all the important information thanks
    to different methods, permitting to access the XML separately. As the XML output depends on debugging
    and verbose levels, the -v and -d arguments are not permitted, to force a standard XML output.

    This class will be used by every Scanner class to parse it's output and create the network profile
    from that output. Instances attribute MONTH_EQ is a dictionary used to parse String months to a numeric value.

        :param xml_string: Variable containing all the XML output
        :type xml_string: str, bytes

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
        return self.__xml_string

    @property
    def tree(self):
        return self.__xml_iterable_tree

    @property
    def parsed_info(self):
        return self.__parsed_info

    @xml_string.setter
    def xml_string(self, value):
        self.__xml_string = value
        assert isinstance(self.xml_string, str)

    def __parse_xml(self):
        """ Parses a string as an XML tree.

            :return: XML Root
        """
        return ET.fromstring(self.xml_string)

    def __parse_running_info(self):
        """ Parse all general scanning info into a dictionary.
        """
        parsed_dictionary = {}
        for attribute, value in self.tree.attrib.items():
            if 'startstr' in attribute:
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
            else:
                continue

        for attribute, value in self.tree.find('.//finished').attrib.items():
            if 'summary' in attribute:
                parsed_dictionary['summary'] = value
            elif 'timestr' in attribute:
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
            else:
                continue

        self.parsed_info['running_info'] = parsed_dictionary
        # return parsed_dictionary

    def __parse_scan_info(self):
        """ Parse all scan type related info, including scan types, number of services and services themselves.

            :return: Dictionary with all the scan type info
            :rtype: dict
        """
        parsed_dictionary = {}

        scan_info_element = self.tree.find('.//scaninfo')
        current_scan_tag_attributes = scan_info_element.attrib
        parsed_dictionary[current_scan_tag_attributes['protocol']] = {
            'type': current_scan_tag_attributes['type'],
            'numservices': current_scan_tag_attributes['numservices'],
            'services': current_scan_tag_attributes['services']
        }

        self.parsed_info['scan_info'] = parsed_dictionary

    def __parse_hosts_info(self):
        """ Parse all host scan related info, including scanned ports, hostnames, operating systems and
        script execution results
        """

        for host in self.tree.findall('.//host'):
            # IP Address parsing
            try:
                current_ip = host.find('address').attrib['addr']
            except (KeyError, IndexError):
                raise XMLParsingError('Could not parse host\'s ip address.')

            try:
                self.parsed_info['scan'][current_ip] = {}
            except KeyError:
                self.parsed_info['scan'] = {current_ip: {}}

            # Host status parsing
            status_element = host.find('status')
            try:
                self.parsed_info['scan'][current_ip]['state'] = status_element.attrib['state']
                self.parsed_info['scan'][current_ip]['reason'] = status_element.attrib['reason']
            except (KeyError, IndexError):
                raise XMLParsingError('Could not parse host\'s state.')

            # Hostnames parsing
            hostnames_element = host.find('hostnames')
            self.parsed_info['scan'][current_ip]['hostnames'] = []
            for hostname in hostnames_element.findall('hostname'):
                try:
                    self.parsed_info['scan'][current_ip]['hostnames'].append(hostname.attrib['name'])
                except (KeyError, IndexError):
                    raise XMLParsingError('Error while parsing hostnames from {}'.format(current_ip))

            # Port info parsing
            # For each protocol scanned, previously parsed into the 'scan_info' as keys
            for protocol in self.parsed_info['scan_info']:
                # Add 'protocols' key with every protocol scan inside
                self.parsed_info['scan'][current_ip]['protocols'] = {protocol: {}}

                port_predicate = ".//ports/port[@protocol=\'" + protocol + "\']"
                state_predicate = port_predicate + '/state'
                # For each port and port status on that protocol
                for port_element, state_element in zip(host.findall(port_predicate), host.findall(state_predicate)):
                    self.parsed_info['scan'][current_ip]['protocols'][protocol][port_element.attrib['portid']] = {
                        'state': state_element.attrib['state'],
                        'reason': state_element.attrib['reason'],
                        'service': None
                    }
                    # Get service information
                    service_element = port_element.find('service')
                    if service_element is not None:
                        name = service_element.attrib['name'] \
                            if 'name' in service_element.attrib else None
                        product = service_element.attrib['product'] \
                            if 'product' in service_element.attrib else None
                        version = service_element.attrib['version'] \
                            if 'version' in service_element.attrib else None
                        extrainfo = service_element.attrib['extrainfo'] \
                            if 'extrainfo' in service_element.attrib else None
                        cpe = service_element.attrib['cpe'] \
                            if 'cpe' in service_element.attrib else None

                        # Instantiate a Service with all the information gathered
                        self.parsed_info['scan'][current_ip]['protocols'][protocol][port_element.attrib['portid']][
                            'service'] = Service(name, product, version, extrainfo, cpe)

                # OS information
                self.parsed_info['scan'][current_ip]['os'] = {'matches': [], 'fingerprint': None}
                for os_match in host.findall('.//osmatch'):
                    self.parsed_info['scan'][current_ip]['os']['matches'].append({
                        'name': os_match.attrib['name'],
                        'accuracy': os_match.attrib['accuracy']
                    })
                # Sort OS Matches in descending order by accuracy
                self.parsed_info['scan'][current_ip]['os']['matches'].sort(key=lambda k: k['accuracy'], reverse=True)

                # OS fingerprint
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
        :param cpe: Service CPE
        :param scripts: Scripts information
        :type name: str
        :type product: str
        :type version: str
        :type extrainfo: str
        :type cpe: str
        :type scripts: dict
    """

    def __init__(self, name, product, version, extrainfo, cpe, scripts=None):
        # Solve scripts={} default value causing dictionary mutability
        if scripts is None:
            scripts = dict()
        self.name = name
        self.product = product
        self.version = version
        self.extrainfo = extrainfo
        self.cpe = cpe
        self.scripts = scripts

    @property
    def name(self):
        return self.__name

    @property
    def product(self):
        return self.__product

    @property
    def version(self):
        return self.__version

    @property
    def extrainfo(self):
        return self.__extrainfo

    @property
    def cpe(self):
        return self.__extrainfo

    @property
    def scripts(self):
        return self.__scripts

    @name.setter
    def name(self, name):
        """ name attribute setter

            :param name: Service name
            :type name: str
            :raises: AssertionError
        """
        self.__name = name
        assert isinstance(self.name, str) or self.name is None

    @product.setter
    def product(self, product):
        """ product attribute setter

            :param product: Service product
            :type product: str
            :raises: AssertionError
        """
        self.__product = product
        assert isinstance(self.product, str) or self.product is None

    @version.setter
    def version(self, version):
        """ version attribute setter

            :param version: Service version
            :type version: str
            :raises: AssertionError
        """
        self.__version = version
        assert  isinstance(self.version, str) or self.version is None

    @extrainfo.setter
    def extrainfo(self, extrainfo):
        """ extrainfo attribute setter

            :param extrainfo: Service Extrainfo
            :type extrainfo: str
            :raises: AssertionError
        """
        self.__extrainfo = extrainfo
        assert isinstance(self.extrainfo, str) or self.extrainfo is None

    @cpe.setter
    def cpe(self, cpe):
        """ cpe attribute setter

            :param cpe: Service CPE
            :type cpe: str
            :raises: AssertionError
        """
        self.__cpe = cpe
        assert isinstance(self.cpe, str) or self.cpe is None

    @scripts.setter
    def scripts(self, scripts):
        """ scripts attribute setter

        :param scripts: Scripts dictionary
        :type scripts: dict
        :raises: AssertionError
        """
        self.__scripts = scripts
        assert isinstance(self.scripts, dict)

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

        del self.scripts[name]

    def __getitem__(self, name):
        """ Get an script output searching by it's name

            :param name: Name of the script
            :type name: str
        """

        return self.scripts[name]

    def __str__(self):
        """ Instance string formatting

            :return: String representation of the class
            :rtype: str
        """
        # If all class attributes are None, print a message
        attributes_list = [self.__dict__[a] for a in self.__dict__ if a.startswith('__') and
                           not a.endswith('__')]
        if all(a is None for a in attributes_list):
            return "Non existing service"

        base_string = "Name: " + self.name if self.name is not None else 'Unknown'
        base_string += "Product: " + self.product if self.product is not None else 'Unknown'
        base_string += "Version: " + self.version if self.version is not None else 'Unknown'
        base_string += "Extra info: " + self.extrainfo if self.extrainfo is not None else 'Unknown'
        base_string += "CPE: " + self.cpe if self.cpe is not None else 'Unknown'

        return base_string


class NmapScanner(object):
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

    def __init__(self, **kwargs):
        self.__name = kwargs.get('name')
        self.targets = kwargs.get('targets')
        self.ports = kwargs.get('ports')
        self.scan_arguments = kwargs.get('arguments')
        self.__start_timestamp = None
        self.__exit_status = None
        self.__start_time = None
        self.__args = None
        self.__summary = None
        self.__version = None
        self.__end_time = None
        self.__end_timestamp = None
        self.__scanned_protocols_info = None

        self.__result = None
        self.__tolerant_errors = None

        self.__finished = False

    @property
    def name(self):
        return self.__name

    @property
    def targets(self):
        return self.__targets

    @property
    def ports(self):
        return self.__ports

    @property
    def scan_arguments(self):
        return self.__scan_arguments

    @property
    def start_timestamp(self):
        return self.__start_timestamp

    @property
    def exit_status(self):
        return self.__exit_status

    @property
    def start_time(self):
        return self.__start_time

    @property
    def args(self):
        return self.__args

    @property
    def summary(self):
        return self.__summary

    @property
    def version(self):
        return self.__version

    @property
    def end_time(self):
        return self.__end_time

    @property
    def end_timestamp(self):
        return self.__end_timestamp

    @property
    def tolerant_errors(self):
        return self.__tolerant_errors

    @property
    def scanned_protocols_info(self):
        return self.__scanned_protocols_info

    @property
    def finished(self):
        return self.__finished

    @name.setter
    def name(self, name):
        """ name attribute setter

            :param name: Name of the scanner.
            :type name: str
            :raises: AssertionError
        """
        self.__name = name
        assert isinstance(self.name, str)

    @targets.setter
    def targets(self, targets):
        """ targets attribute setter

            :param targets: Targets list or string
            :type targets: str, list
            :raises: AssertionError
        """
        if targets is None:
            self.__targets = None
        elif isinstance(targets, str):
            self.__targets = self.__parse_targets(targets)
        elif isinstance(targets, list):
            for i in targets:
                if not self.__is_ip_address(i):
                    raise MalformedIpAddressError('Invalid IP Address on setter: {}'.format(i))
            self.__targets = targets
        else:
            raise InvalidArgumentError('Scanner targets must be a string or a list.')

        assert isinstance(self.targets, list) or self.targets is None

    @ports.setter
    def ports(self, ports):
        """ ports attribute setter

            :param ports: Port list or string
            :type ports: str, list
            :raises: AssertionError
        """
        if ports is None:
            self.__ports = None
        elif isinstance(ports, str):
            self.__ports = self.__parse_ports(ports)
        elif isinstance(ports, list):
            for i in ports:
                if not self.__is_valid_port(i):
                    raise InvalidPortError('Invalid port on setter: {}'.format(i))
            self.__ports = ports
        else:
            raise InvalidArgumentError('Scanner ports must be a string or a lit of ports')

        assert isinstance(self.ports, list) or self.ports is None

    @scan_arguments.setter
    def scan_arguments(self, arguments):
        """ scan_arguments setter

            :param arguments: Arguments list or string
            :type arguments: str, list
            :raises: AssertionError
        """
        if arguments is None:
            self.__scan_arguments = arguments

        elif isinstance(arguments, str):
            self.__scan_arguments = self.__parse_arguments(arguments)

        elif isinstance(arguments, list):
            self.__scan_arguments = arguments

        else:
            raise InvalidArgumentError('Scanner arguments must be a string or a list of arguments.')

        assert isinstance(self.scan_arguments, list) or arguments is None

    def __is_valid_port(self, port):
        """Checks if a given value might be an existing port

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

    def __parse_ports(self, ports):
        """ Returns a list containing all ports specified by the -p parameter.

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
        port_list = []
        ports_string = ports.replace(' ', '')

        for split_ports in ports_string.split(','):
            if '-' in split_ports:
                port_range = split_ports.split('-')
                try:
                    first_port_range = int(port_range[0])
                except ValueError:
                    first_port = port_range[0] if len(port_range[0]) else 'None'
                    raise InvalidPortError('Invalid starting port range: {}'.format(first_port))
                try:
                    last_port_range = int(port_range[1]) + 1
                except IndexError:
                    raise InvalidPortError('End of port range in {}- not specified'.format(port_range[0]))
                except ValueError:
                    raise InvalidPortError('Invalid ending port range: {} '.format(port_range[1]))
                for single_port in range(first_port_range, last_port_range):
                    if self.__is_valid_port(single_port):
                        port_list.append(single_port)
                    else:
                        raise InvalidPortError('{} is not a correct port'.format(single_port))
            else:
                if len(split_ports):
                    try:
                        integer_parsed_port = int(split_ports)
                    except ValueError:
                        raise InvalidPortError('Invalid port: {}'.format(split_ports))
                    if self.__is_valid_port(integer_parsed_port):
                        port_list.append(integer_parsed_port)
                    else:
                        raise InvalidPortError('{} is not a correct port.'.format(integer_parsed_port))

        return sorted(list(set(port_list)))

    def __is_ip_address(self, ip_address):
        """Checks if a given IP address is correctly formed.

            :param ip_address: IP address to check
            :type ip_address: str
            :return: True if it is a valid IP Address, False if not
            :rtype: bool
        """
        ip_address_regex = re.compile('^(([0-9]|[1-9][0-9]|1[0-9]{2}|'
                                      '2[0-4][0-9]|25[0-5])\.){3}([0-9]|'
                                      '[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$')

        return ip_address_regex.match(ip_address)

    def __ip_range(self, starting_ip, ending_ip):
        """ Calculates a list of IPs between two given.

            :param starting_ip: Range starting IP address
            :param ending_ip: Range ending IP address
            :type starting_ip: str
            :type ending_ip: str
            :return: list
            """

        split_starting_ip = list(map(int, starting_ip.split('.')))
        split_ending_ip = list(map(int, ending_ip.split('.')))
        ip_range = [starting_ip]

        while split_starting_ip != split_ending_ip:
            split_starting_ip[3] += 1
            for i in [3, 2, 1]:
                if split_starting_ip[i] == 256:
                    split_starting_ip[i] = 0
                    split_starting_ip[i - 1] += 1
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

        ip_addresses = []

        ip_address_netmask = network.replace(' ', '').split('/')
        if len(ip_address_netmask) != 2:
            raise MalformedIpAddressError('Invalid network to dispatch: {}.'
                                          ' Need an IP address and CIDR Mask like 192.168.1.0/24'
                                          .format(ip_address_netmask))

        ip_address = ip_address_netmask[0]
        try:
            cidr = int(ip_address_netmask[1])
        except ValueError:
            raise MalformedIpAddressError('Invalid CIDR format: {}'.format(ip_address_netmask[1]))

        if cidr < 0 or cidr > 32:
            raise MalformedIpAddressError('Out of range CIDR: {}'.format(cidr))

        if not self.__is_ip_address(ip_address):
            raise MalformedIpAddressError('Invalid network IP: {}.'.format(ip_address))

        host_bits = 32 - cidr
        aux = struct.unpack('>I', socket.inet_aton(ip_address))[0]
        start = (aux >> host_bits) << host_bits
        end = start | ((1 << host_bits) - 1)

        for ip in range(start, end):
            ip_addresses.append(socket.inet_ntoa(struct.pack('>I', ip)))

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

        target_list = []
        targets_string = targets.replace(' ', '')

        for split_target in targets_string.split(','):
            if '-' in split_target:
                ip_range = split_target.split('-')
                starting_ip = ip_range[0]
                if not self.__is_ip_address(starting_ip):
                    print('\'' + starting_ip + '\'')
                    raise MalformedIpAddressError('Invalid starting IP range: {}'.format(starting_ip))
                ending_ip = ip_range[1]
                if not self.__is_ip_address(ending_ip):
                    raise MalformedIpAddressError('Invalid ending IP range: {}'.format(ending_ip))
                for single_target_in_range in self.__ip_range(starting_ip, ending_ip):
                    if self.__is_ip_address(single_target_in_range):
                        target_list.append(single_target_in_range)
                    else:
                        raise MalformedIpAddressError('Invalid IP Address: {}'.format(single_target_in_range))
            elif '/' in split_target:
                target_list.extend(self.__dispatch_network(split_target))
            else:
                if self.__is_ip_address(split_target):
                    target_list.append(split_target)
                else:
                    raise MalformedIpAddressError('Invalid IP Address: {}'.format(split_target))

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

        if '-o' in arguments_string:
            raise InvalidArgumentError('You cannot output the scan information, user must manually export it.')

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
        """

        if self.targets is None or not len(self.targets):
            raise NmapScanError('You must specify targets to scan.')

        # Add the XML output format, build the hole nmap command.
        to_execute = ['nmap', '-oX', '-'] + self.scan_arguments
        # If ports specified, add them as -p parameter, in other case ports will be automatically chosen
        if self.ports is not None:
            to_execute.append('-p')
            to_execute.extend(','.join([str(p) for p in self.ports]))
        # Add the targets
        to_execute += self.targets

        print('LLamando a proceso')

        # Call and block a subproccess, then redirect output and errors to a variable each.
        nmap_process = subprocess.Popen(to_execute, bufsize=-1, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = nmap_process.communicate()
        print('Terminado el proceso')
        # If there is output
        if len(output):
            try:
                parsed_nmap_output = _XMLParser(output).parse()

            # If parsing error raise NmapScanError with STDERR info.
            except ET.ParseError:
                raise NmapScanError('Could not parse output from nmap. STDERR says:\r\n' + error)

        # If there is no output, raise NmapScanError with STDERR info
        else:
            raise NmapScanError('No output from process was given. STDERR says:\r\n' + error)

        # If any error but method reaches this point, there are tolerant errors.
        if len(error):
            self.__tolerant_errors = error

        # Assign class attributes from the parsed information.
        self.__assign_class_attributes(parsed_nmap_output)
        # Set finished variable to True
        self.__finished = True

    def __assign_class_attributes(self, nmap_output):
        """ Assign class attributes (properties) from the dictionary coming from the parsed XML.

            :param nmap_output:
            :type nmap_output: dict
        """

        self.__start_timestamp = nmap_output['running_info']['start_timestamp']
        self.__exit_status = nmap_output['running_info']['exit_status']
        self.__start_time = nmap_output['running_info']['start_time']
        self.__args = nmap_output['running_info']['args']
        self.__summary = nmap_output['running_info']['summary']
        self.__version = nmap_output['running_info']['version']
        self.__end_time = nmap_output['running_info']['end_time']
        self.__end_timestamp = nmap_output['running_info']['end_timestamp']
        self.__scanned_protocols_info = nmap_output['scan_info']
        self.__result = nmap_output['scan']

    def __has_finished(self):
        """ Raises NmapScannerError if scanner has not finished or was not performed.

            :raises: NmapScanError
        """

        if not self.finished:
            raise NmapScanError('Scan was not completed or was not even launched.')

    def raw_data(self):
        """ Returns the parsed dictionary itself containing all the scan information.

            :return: Structured nested dictionary
            :rtype: dict
        """

        self.__has_finished()
        return self.__result

    def hostnames(self, host):
        """ Returns a list containing all hostnames from a given host, eliminating duplicates.

            :param host: Host where to get the hostnames from.
            :type host: str
            :return: List of hostnames,.
            :rtype: list
        """

        self.__has_finished()
        return list(set(self.__result[host]['hostnames']))

    def scanned_hosts(self):
        """Get a list of all hosts that responded to the scan.

            :return: List of hosts that responded to to the scan
            :rtype: list
        """

        self.__has_finished()
        return [r for r in self.__result]

    def non_scanned_hosts(self):
        """Get a list of all hosts that did not respond to the scan.

            :return: List of non scanned hosts
            :rtype: list
        """

        self.__has_finished()
        return [t for t in self.targets if t not in self.__result]

    def non_scanned_ports(self):
        """ Get a list of non scanned ports, check for every port between 1 and 65535. This method will only work
        if self.ports was specified.

            :return: List of non scanned ports
            :rtype: list
        """

        self.__has_finished()
        if self.ports is not None:
            return [p for p in range(0, 65536) if p not in self.ports]
        return []

    def os_matches(self, host):
        """ Yield every OS name and accuracy for every OS match from a given host.

            :param host: Host where to get the os info from.
            :type host: str
            :return: OS name and accuracy for every os match
            :rtype: tuple
        """

        self.__has_finished()
        for name, accuracy in self.__result[host]['os']['matches']:
            yield name, accuracy

    def os_fingerprint(self, host):
        """ Returns the OS fingerprint from a given host. If there is no fingerprint match or the host was not scanned,
        it will return None.

            :param host: Host where to get the os fingerprint from.
            :type host: str
            :return: OS fingerprint. None if there is no fingerprint or there is no such host
            :rtype: str, None
        """

        self.__has_finished()
        try:
            return self.__result[host]['os']['fingerprint']
        except KeyError:
            return None

    def most_accurate_os(self, host):
        """ Returns a list of the most accurate OS matches for a given host. If there is no OS match or no OS match was
        performed, it will return None.

            :param host: Host where to get the most accurate OSes.
            :type host: str
            :return: List of most accurate OSes.
            :rtype: list
        """

        self.__has_finished()
        try:
            best_accuracy = self.__result[host]['os']['matches'][0]['accuracy']
        except KeyError:
            return None

        return [o for o in self.__result[host]['os']['matches']['name']
                if self.__result[host]['os']['matches']['accuracy'] == best_accuracy]

    def state(self, host):
        """ Return the state of a host. It returns None if the host was not scanned.

            :param host: Host where to get the state from.
            :type host: str
            :return: Host's state. None if the host does not exists
            :rtype: str, None
        """

        self.__has_finished()
        try:
            return self.__result[host]['state']
        except KeyError:
            return None

    def reason(self, host):
        """ Returns the reason why a host was successfully scanned. It returns None if the host was not scanned

            :param host: Host where to get the reason from.
            :type host: str
            :return: Reason from scan success. None if host does not exists.
            :rtype: str, None
        """

        self.__has_finished()
        try:
            return self.__result[host]['reason']
        except KeyError:
            return None

    def all_protocols(self, host):
        """ Yields all scanned protocols from a host.

            :param host: Host where to get the protocols from.
            :type host: str
            :return: Iterable with all scanned protocol
            :rtype: str
        """

        self.__has_finished()
        try:
            for proto in self.__result[host]['protocols']:
                yield proto
        except KeyError:
            yield

    def scanned_ports(self, host, protocol):
        """ Yields all scanned ports for a given host and protocol.

            :param host: Host where to get the ports from.
            :param protocol: Protocol specification of the ports.
            :type host: str
            :type protocol: str
            :return: Iterable with all scanned ports for a given protocol. None if no host/protocol is found
            :rtype: str, None
        """

        self.__has_finished()
        try:
            for port in self.__result[host]['protocols'][protocol]:
                yield port
        except KeyError:
            yield

    def port_info(self, host, protocol, port):
        """ Return a Service instance containing all the information from a port, given a host and a protocol.

            :param host: Host where to get the port info from
            :param protocol: Protocol specification of the port.
            :param port: Target port
            :type host: str
            :type protocol: str
            :type port: str, int
            :return: Service from a port
            :rtype: Service
        """

        self.__has_finished()
        try:
            return self.__result[host]['protocols'][protocol][str(port)]['service']
        except KeyError:
            return None

    def standard_port_info(self, host, protocol, port):
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
            :returns: tuple(name, service_info)
                WHERE
                name is the service name, None if it does not exist.
                service_info is the service information standard output. None if it does not exist.
        """

        self.__has_finished()
        try:
            service_instance = self.__result[host]['protocols'][protocol][str(port)]['service']
        except KeyError:
            return None, None

        if service_instance is None:
            return None, None

        product = service_instance.product if service_instance.product is not None else ''
        version = service_instance.version if service_instance.version is not None else ''
        extrainfo = service_instance.extrainfo if service_instance.version is not None else ''
        service_detection_info = ' '.join([product, version, extrainfo])

        return service_instance.name, service_detection_info

    def port_scripts(self, host, protocol, port):
        """ Yields all scripts names and output that where executed for a specific port.

            :param host: Host where to get the port info from
            :param protocol: Protocol specification of the port
            :param port: Target port
            :type host: str
            :type protocol: str
            :type port: int, str
            :returns: tuple(name, output)
                WHERE
                name is the script name
                output is the script execution output.
        """

        self.__has_finished()
        try:
            service_instance = self.__result[host]['protocols'][protocol][str(port)]['service']
        except KeyError:
            yield
            return

        if service_instance is None:
            yield
            return

        for name, output in service_instance.scripts.items():
            yield name, output


class AsyncNmapScanner(NmapScanner):

    def __init__(self, **kwargs):
        NmapScanner.__init__(self, **kwargs)
        self.__mute_error = kwargs.get('mute_error') if kwargs.get('mute_error') is not None else False
        self.__had_errors = False
        self.__running = False
        self.__exception_stack = []

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
                self.__had_errors = True
                self.__running = False
            else:
                self.__running = False
                raise NmapScanError('You must specify targets to scan.')

        parsed_nmap_output = None

        if not self.__had_errors:
            # Add the XML output format, build the hole nmap command.
            to_execute = ['nmap', '-oX', '-'] + self.scan_arguments
            # If ports specified, add them as -p parameter, in other case ports will be automatically chosen
            if self.ports is not None:
                to_execute.append('-p')
                to_execute.extend(','.join([str(p) for p in self.ports]))
            # Add the targets
            to_execute += self.targets

            # Call and block a subproccess, then redirect output and errors to a variable each.
            nmap_process = subprocess.Popen(to_execute, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                            universal_newlines=True)
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
                        self.__had_errors = True
                        self.__running = False
                    else:
                        self.__running = False
                        raise NmapScanError('Could not parse output from nmap. STDERR says:\r\n' + error)

            # If there is no output, raise NmapScanError with STDERR info
            else:
                if self.__mute_error:
                    self.__exception_stack.append(NmapScanError('Could not parse output from nmap. STDERR says:\r\n'
                                                                + error))
                    self.__had_errors = True
                    self.__running = False
                else:
                    self.__running = False
                    raise NmapScanError('No output from process was given. STDERR says:\r\n' + error)

            # If any error but method reaches this point, there are tolerant errors.
            if len(error) and not self.__had_errors:
                self.__tolerant_errors = error

            if not self.__had_errors:
                # Assign class attributes from the parsed information.
                self.__assign_class_attributes(parsed_nmap_output)

            # Set finished variable to True
            self.__finished = True
            self.__running = False

    def fatal_errors(self):
        return self.__exception_stack

    def is_running(self):
        return self.__running

    def run(self):
        """ Creates a Thread and executes the __background_run() method, which is the normal NmapScanner.run()
        but with some variations adapted to the Async class attributes.
        """
        exec_thread = threading.Thread(target=self.__background_run, args=[])
        print (self.__mute_error)
        exec_thread.start()


class ScanQueue:
    """ Class containing any number of AsyncNmapScanner instances that provides controlled execution over them.

        Allows to execute all queued scans or particular scans by number and/or name. It also allows to
        add, modify or delete existing scans in the queue. The __init__ function stores any number of
        AsyncNmapScanner instances.

            :param args:
            WHERE
                each arg in args is an AsyncNmapScanner instance.
    """

    def __init__(self, *args):
        self.__asyc_scanners = args
        self.__currently_scanning = []
        self.__fnished_scanning = []
        self.__started = False

        self.__assert_attributes()

    def __assert_attributes(self):
        """ Assert that all scanners in queue are async scanners"""
        assert all(isinstance(s, AsyncNmapScanner) for s in self.__asyc_scanners)

    def __start_scan_watch(self):
        """ Background check on running scans. If any scan has finished, it is moved to the finished
        queue.
        """

        def __scan_watch(self):
            print("Entrando en scan watch.")
            while True:
                for s in range(len(self.__currently_scanning)):
                    if not self.__currently_scanning[s].is_running():
                        del self.__async_scanners[s]
                if not len(self.__currently_scanning):
                    break
                time.sleep(1)

            self.__started = False

        watch_thread = threading.Thread(target=__scan_watch, args=[self])
        watch_thread.start()

    def run_all(self):
        """ Runs every AsyncNmapScanner in queue and sets the __currently_running attribute to every
        AsyncNmapScanner instance.
        """
        self.__started = True
        for s in self.__asyc_scanners:
            self.__currently_scanning.append(s)
            s.run()

        self.__start_scan_watch()

    def run_specific(self, *args):
        """ Runs specific scanners in queue, searching by name or position.
            :param args:
            WHERE
                each arg in args is an AsyncNmapScanner name or position in queue, str or int
        """

        for arg in args:
            # If an argument is a string
            if isinstance(arg, str):
                # Variable storing if at least one scan executed
                one_executed = False
                # Loop through scanners
                for sc in self.__asyc_scanners:
                    # If scanner has that name and it is not being executed
                    if sc.name == arg and sc not in self.__currently_scanning:
                        # Run and add to currently executing
                        self.__currently_scanning.append(sc)
                        sc.run()
                        # Store that at least one executed
                        one_executed = True
                        # Set started to True
                        self.__started = False
                # If no scans executed
                if not one_executed:
                    # Raise exception
                    raise ScanQueueError('There is not scanner with such name in the queue: {}'.format(arg))

            # If an argument is an integer
            elif isinstance(arg, int):
                try:
                    # Directly execute that scanner and add to currently executing
                    self.__asyc_scanners[arg].run()
                    self.__currently_scanning.append(self.__asyc_scanners[arg])
                    # Set started to True
                    self.__started = True
                except IndexError:
                    # If KeyError, scan does not exist. Raise exception
                    raise ScanQueueError('Scanner with position {} does not exist in queue'.format(arg))

            # If wrong type argument. Raise exception
            else:
                raise ScanQueueError('run_specific() method parameters must be AsyncNmapScanner '
                                     'instance\'s name or position (int or str)')

            # Start watcher
            if self.__started:
                self.__start_scan_watch()

    def queued_finished(self):
        """ Checks if all queued scans that where executed have finished.

            :return: True if they all have finished. False if not.
            :rtype: bool
            :raises: ScanQueueError
        """
        # If no scans active, return True.
        if not len(self.__currently_scanning):
            return True

        return False

    def finished_scans(self):
        """ Yields all finished scans

            :return: Iterable of AsyncNmapScanners that have finished.
        """
        for s in self.__fnished_scanning:
            yield s


if __name__ == '__main__':

    first_scanner = NmapScanner(name='hola', ports='1-20', targets='127.0.0.1', arguments='-sT')
    second_scanner = NmapScanner(name='christian', ports=range(50,101), targets='127.0.0.1', arguments='-sV')

    first_scanner.run()
    print(first_scanner.raw_data())
    second_scanner.run()
    print(second_scanner.raw_data())
    """
    queue = ScanQueue(first_scanner, second_scanner)

    queue.run_all()
    while not queue.queued_finished():
        print('Esperandoooooo')
        time.sleep(2)

    print("Saliendo de la espera!")

    scanners_list = queue.finished_scans()
    """
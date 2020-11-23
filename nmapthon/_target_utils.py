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
# FITNESS FOR A PARTICULAR PURPOSE AND NON INFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import re
import socket
import struct

from .exceptions import MalformedIpAddressError

_BASE_IP_REGEX = '(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}' \
                 '([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])'

_SINGLE_IP_ADDRESS_REGEX = re.compile('^{}$'.format(_BASE_IP_REGEX))

_IP_ADDRESS_WITH_CIDR_REGEX = re.compile('^{}/([0-9]|[1-2][0-9]|3[0-2])$'.format(_BASE_IP_REGEX))

_IP_RANGE_REGEX = re.compile('^{}-{}$'.format(_BASE_IP_REGEX, _BASE_IP_REGEX))

_OCTECT_RANGE_REGEX = '(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))'

_PARTIAL_IP_RANGE_REGEX = re.compile('{}(-{})?\.{}(-{})?\.{}(-{})?\.{}(-{})?'.format(*[_OCTECT_RANGE_REGEX for _ in range(8)]))


def is_ip_address(ip_address):
    """Checks if a given IP address is correctly formed.

        :param ip_address: IP address to check
        :type ip_address: str
        :return: True if it is a valid IP Address, False if not
        :rtype: bool
    """

    # Return True if matches, False if not.
    return _SINGLE_IP_ADDRESS_REGEX.fullmatch(ip_address)


def ip_range(starting_ip, ending_ip):
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


def partial_ip_range(ip_addr):
    """ Calculates the list of IP address from a partial ranged IP expression.

        :param ip_addr: IP Address from where to extract the IP s
        :type ip_addr: str
        :returns: List of IPs in partial range
        :rtype: list
    """

    # Split by dots
    split_ip = ip_addr.split('.')
    # IPs to return
    ips=[]
    # List to store each part range
    partial_ranges = []
    # For each partial IPs part
    for i in split_ip:
        # If its a range
        if '-' in i:
            # Extract the list of numbers between
            partial_range = i.split('-')
            try:
                start = int(partial_range[0])
            except ValueError:
                raise MalformedIpAddressError('Invalid start of range, expected number but got : {}'.format(partial_range[0]))
            try:
                end = int(partial_range[1])
            except ValueError:
                raise MalformedIpAddressError('Invalid start of range, expected number but got : {}'.format(partial_range[1]))

            if not 0 <= start <= end <= 255:
                raise MalformedIpAddressError('Start range must be lower than end range, and both between 0 adn 255')

            partial_ranges.append(list(range(start, end + 1)))

        # If not, add a list with a single element
        else:
            partial_ranges.append([i])
    
    # Combine them all
    for first in partial_ranges[0]:
        for second in partial_ranges[1]:
            for third in partial_ranges[2]:
                for forth in partial_ranges[3]:
                    ips.append('.'.join([str(x) for x in [first, second, third, forth]]))
    
    return ips


def dispatch_network(network):
    """ Creates a list of all the IP address inside a network with it's net-mask in CIDR format.

        :param network: Network IP address and /net-mask to dispatch
        :type network: str
        :returns: List of every IP on a network range
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
        raise MalformedIpAddressError('Invalid CIDR format: {}'.format(ip_address_netmask[1])) from None

    # If netmask not between 0 and 32, included, raise Exception
    if not 0 <= cidr <= 32:
        raise MalformedIpAddressError('Out of range CIDR: {}'.format(cidr))

    # If invalid IP address, raise Exception
    if not is_ip_address(ip_address):
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


def parse_targets_from_str(targets):
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
        if _IP_RANGE_REGEX.fullmatch(split_target):
            # Split range
            ip_range_list = split_target.split('-')
            # Get starting IP address from range
            starting_ip = ip_range_list[0]
            # If not a valid IP address, raise Error
            if not is_ip_address(starting_ip):
                raise MalformedIpAddressError('Invalid starting IP range: {}'.format(starting_ip))
            # Get Ending IP address from range
            ending_ip = ip_range_list[1]
            # If not valid IP address, raise Error
            if not is_ip_address(ending_ip):
                raise MalformedIpAddressError('Invalid ending IP range: {}'.format(ending_ip))
            # For every IP in range, add to list if valid IP. If not, raise Exception.
            for single_target_in_range in ip_range(starting_ip, ending_ip):
                if is_ip_address(single_target_in_range):
                    target_list.append(single_target_in_range)
                else:
                    raise MalformedIpAddressError('Invalid IP Address: {}'.format(single_target_in_range))
        # If a slash is found, guess a network mask
        elif _IP_ADDRESS_WITH_CIDR_REGEX.fullmatch(split_target):
            # Extend the list for dispatching the network
            target_list.extend(dispatch_network(split_target))

        # If partial IP addresses
        elif _PARTIAL_IP_RANGE_REGEX.fullmatch(split_target):
            target_list.extend(partial_ip_range(split_target))

        # If it reaches here, guess single IP. Add to list or raise Error if malformed.
        else:
            target_list.append(split_target)

    # Return the sorted list. List is sorted by IP address. Ej: 192.168.1.12 > 192.168.1.9
    return sorted(list(set(target_list)),
                  key=lambda x: x if not _SINGLE_IP_ADDRESS_REGEX.fullmatch(x) else
                  int(''.join(["%02X" % int(i) for i in x.split('.')]), 16))

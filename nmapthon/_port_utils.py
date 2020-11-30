from .exceptions import InvalidPortError


def is_valid_port(port):
    """Checks if a given value might be an existing port. Must be between 1 and 65535, both included.

        :param port: Port candidate
        :type port: int, str
        :returns: True if is valid, False if not
        :rtype: bool
    """
    try:
        int_port = int(port)
    except ValueError:
        return False

    return 0 < int_port < 65536


def parse_ports_from_str(ports):
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
                raise InvalidPortError('Invalid starting port range: {}'.format(first_port)) from None
            # Cast ending port range
            try:
                last_port_range = int(port_range[1]) + 1
            # If IndexError, no ending port range was specified.
            except IndexError:
                raise InvalidPortError('End of port range in {}- not specified'.format(port_range[0])) from None
            # If ValueError, invalid ending for port range.
            except ValueError:
                raise InvalidPortError('Invalid ending port range: {} '.format(port_range[1])) from None
            # For every port in the range calculated
            for single_port in range(first_port_range, last_port_range):
                # If valid port, add to list
                if is_valid_port(single_port):
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
                    raise InvalidPortError('Invalid port: {}'.format(split_ports)) from None
                # If is a valid port, append it to list
                if is_valid_port(integer_parsed_port):
                    port_list.append(integer_parsed_port)
                # If invalid, raise Error
                else:
                    raise InvalidPortError('{} is not a correct port.'.format(integer_parsed_port))

    return sorted(list(set(port_list)))

def single_port_list(port_list):
    """ Transforms a port list with single ports and/or port ranges into a single list with no duplicates.

    :param port_list: Port list to parse
    :type port_list: list
    :returns: List of single and unique ports
    :rtype: list
    """

    # To STR
    port_list = list(map(str, port_list))

    new_port_list = []
    for i in list(map(parse_ports_from_str, port_list)):
        new_port_list.extend(i)
    
    return list(set(new_port_list))


def parse_ports_from_list(port_list):
    """ Parse a list of int/str ports into a single str containing a port range that nmap can understand.

        :param port_list: List of ports
        :type port_list: list
        :return: String representing the ports in nmap syntax
        :rtype: str
    """

    # Get unique list of single ports
    new_port_list = single_port_list(port_list)

    # If not all ports are valid ports, raise NmapScanError
    if not all(is_valid_port(p) for p in new_port_list):
        raise InvalidPortError('Ports must be between 0 and 65536') from None

    # Sort ports in ascending order
    sorted_ports = sorted(new_port_list)
    # Instantiate port string
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

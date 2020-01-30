import sys
import os

PACKAGE_PARENT = '..'
SCRIPT_DIR = os.path.dirname(os.path.realpath(os.path.join(os.getcwd(), os.path.expanduser(__file__))))
sys.path.append(os.path.normpath(os.path.join(SCRIPT_DIR, PACKAGE_PARENT)))

import unittest
import nmapthon


class PortParsingTest(unittest.TestCase):

    def setUp(self):
        self.scanner = nmapthon.NmapScanner('127.0.0.1')
        self.single_port = '80'
        self.comma_split_ports = '10,20,30'
        self.dash_split_ports = '10-15'
        self.combined_split_ports = '80,81-85'
        self.valid_but_duplicated_ports = '63, 63-65'
        self.out_of_range_ports = '65333-65536'
        self.malformed_ports = '80?82'

    def test_single_port(self):
        self.scanner.ports = self.single_port
        self.assertEqual(self.scanner.ports, [80])

    def test_comma_split_ports(self):
        self.scanner.ports = self.comma_split_ports
        self.assertEqual(self.scanner.ports,
                         [10,20,30])

    def test_dash_split_ports(self):
        self.scanner.ports = self.dash_split_ports
        self.assertEqual(self.scanner.ports,
                         [10, 11, 12, 13, 14, 15])

    def test_combined_split_ports(self):
        self.scanner.ports = self.combined_split_ports
        self.assertEqual(self.scanner.ports,
                         [80, 81,  82, 83, 84, 85])

    def test_remove_duplicates(self):
        self.scanner.ports = self.valid_but_duplicated_ports
        self.assertEqual(self.scanner.ports,
                         [63, 64, 65])

    def test_out_of_range_ports(self):
        with self.assertRaises(nmapthon.InvalidPortError):
            self.scanner.ports = self.out_of_range_ports

    def test_malformed_ports(self):
        with self.assertRaises(nmapthon.InvalidPortError):
            self.scanner.ports = self.malformed_ports


if __name__ == '__main__':
    unittest.main()

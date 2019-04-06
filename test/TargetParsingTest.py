import unittest
import nmapthon


class TargetParsingTest(unittest.TestCase):

    def setUp(self):
        self.scanner = nmapthon.NmapScanner()
        self.single_target = '192.168.1.1'
        self.comma_separated_targets = '192.168.1.1, 192.168.1.2'
        self.target_range = '192.168.1.1 - 192.168.1.5'
        self.masked_target = '192.168.1.1/30'
        self.comma_ranged_targets = '192.168.1.1, 192.168.1.2-192.168.1.5'
        self.combined_targets = '192.168.1.0/30, 192.168.1.8-192.168.1.10'
        self.malformed_target = '300.34.56.12'
        self.malformed_cidr = '192.168.1.0/33'

    def test_single_target(self):
        self.scanner.targets = self.single_target
        self.assertEquals(self.scanner.targets, ['192.168.1.1'])

    def test_comma_separated_targets(self):
        self.scanner.targets = self.comma_separated_targets
        self.assertEquals(self.scanner.targets,
                          ['192.168.1.1', '192.168.1.2'])

    def test_target_range(self):
        self.scanner.targets = self.target_range
        self.assertEquals(self.scanner.targets,
                          ['192.168.1.1', '192.168.1.2', '192.168.1.3', '192.168.1.4', '192.168.1.5'])

    def test_masked_target(self):
        self.scanner.targets = self.masked_target
        self.assertEquals(self.scanner.targets,
                          ['192.168.1.1', '192.168.1.2'])

    def test_comma_ranged_targets(self):
        self.scanner.targets = self.comma_ranged_targets
        self.assertEquals(self.scanner.targets,
                          ['192.168.1.1', '192.168.1.2', '192.168.1.3', '192.168.1.4', '192.168.1.5'])

    def test_combined_targets(self):
        self.scanner.targets = self.combined_targets
        self.assertSequenceEqual(self.scanner.targets,
                                 ['192.168.1.1', '192.168.1.2', '192.168.1.8', '192.168.1.9', '192.168.1.10'])

    def test_malformed_target(self):
        with self.assertRaises(nmapthon.MalformedIpAddressError):
            self.scanner.targets = self.malformed_target

    def test_malformed_cidr(self):
        with self.assertRaises(nmapthon.MalformedIpAddressError):
            self.scanner.targets = self.malformed_cidr


if __name__ == '__main__':
    unittest.main()

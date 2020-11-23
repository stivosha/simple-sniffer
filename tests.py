import unittest
import main


class TestStringMethods(unittest.TestCase):

    def test_parse_ipv4_addr(self):
        gotten, expected = main.get_ipv4_addr(b'\x08\x08\x08\x08'), '8.8.8.8'
        self.assertEqual(gotten, expected)
        gotten, expected = main.get_ipv4_addr(b'\x7f\x00\x00\x01'), '127.0.0.1'
        self.assertEqual(gotten, expected)

    def test_parse_mac_addr(self):
        (gotten, expected) = main.get_mac_addr(b'\x00\x00\x00\x00\x00\x00'), '00:00:00:00:00:00'
        self.assertEqual(gotten, expected)
        (gotten, expected) = main.get_mac_addr(b'\xFF\xFF\xFF\xFF\xFF\xFF'), 'FF:FF:FF:FF:FF:FF'
        self.assertEqual(gotten, expected)


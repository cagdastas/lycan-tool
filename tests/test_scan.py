"""scan testleri. Çalıştırma: python -m unittest"""

import unittest

from lycan import scan


class IsExposed(unittest.TestCase):
    def test_only_this_computer(self):
        for address in ["127.0.0.1", "::1"]:
            self.assertFalse(scan.is_exposed(address))

    def test_reachable_from_network(self):
        for address in ["0.0.0.0", "::", "192.168.1.100", "10.0.0.5"]:
            self.assertTrue(scan.is_exposed(address))


if __name__ == "__main__":
    unittest.main()

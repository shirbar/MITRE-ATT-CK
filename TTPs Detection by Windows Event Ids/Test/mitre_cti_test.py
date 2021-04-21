import unittest
import os
import sys



class MyTestCase(unittest.TestCase):
    def test_get_mitre_cti_hash_map(self):
        sys.path.append("../")
        print("Running MITRE CTI calculate HashMap Test")
        from ..Methods.MITRECti import get_mitre_cti_hash_map
        get_mitre_cti_hash_map()
        self.assertTrue(True)


if __name__ == '__main__':
    unittest.main()

from unittest import TestCase


class Test(TestCase):
    def test_get_mitre_cti_hash_map(self):
        from Methods.MITRECti import get_mitre_cti_hash_map
        get_mitre_cti_hash_map()
        self.assertTrue(True)

from unittest import TestCase

class Test(TestCase):
    def test_get_event_list_hash_map(self):
        from Methods.EventList import get_event_list_hash_map
        get_event_list_hash_map()
        self.assertTrue(True)

import unittest
from pwned import isHashPwnedLocalZip


class TestIsHashPwnedLocalZip(unittest.TestCase):
    def test_valid_hash(self):
        self.assertTrue(isHashPwnedLocalZip("5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8", "local_db_file", "local_zip_file"))

    def test_invalid_hash(self):
        self.assertFalse(isHashPwnedLocalZip("invalid_hash", "local_db_file", "local_zip_file"))

    def test_empty_hash(self):
        self.assertFalse(isHashPwnedLocalZip("", "local_db_file", "local_zip_file"))

    def test_none_hash(self):
        self.assertFalse(isHashPwnedLocalZip(None, "local_db_file", "local_zip_file"))

if __name__ == '__main__':
    unittest.main()
    
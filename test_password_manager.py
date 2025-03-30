import unittest
from parola_yoneticisi import PasswordManagerLogic

class TestPasswordManager(unittest.TestCase):
    def setUp(self):
        self.pm = PasswordManagerLogic()

    def test_parola_uret(self):
        parola = self.pm.parola_uret(12)
        self.assertEqual(len(parola), 12)
        self.assertTrue(any(c.isupper() for c in parola))

    def test_parola_hashle(self):
        hash1 = self.pm.parola_hashle("test123")
        self.assertTrue(self.pm.parola_dogrula("test123", hash1))
        self.assertFalse(self.pm.parola_dogrula("wrong", hash1))

if __name__ == "__main__":
    unittest.main()
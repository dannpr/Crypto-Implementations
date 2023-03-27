import unittest
from algebra import int_to_bytes
from elgamal import EG_generate_keys, EGM_encrypt, EGA_encrypt, EG_decrypt, bruteLog, PARAM_P, PARAM_G


class TestCryptography(unittest.TestCase):

    def test_EG_generate_keys(self):
        self.assertTrue(EG_generate_keys())

    def test_EGM_encrypt_decrypt(self):
        key = EG_generate_keys()
        (u, U) = key

        m1 = 0x2661b673f687c5c3142f806d500d2ce57b1182c9b25bfe4fa09529424b
        m2 = 0x1c1c871caabca15828cf08ee3aa3199000b94ed15e743c3

        (r1, c1) = EGM_encrypt(m1, U)
        (r2, c2) = EGM_encrypt(m2, U)

        (r3, c3) = (r1*r2, c1*c2)

        m3 = EG_decrypt(r3, c3, u)

        print(int_to_bytes(m3))
        m = m1*m2
        self.assertEqual(m3, m)

    def test_EGA_encrypt_decrypt(self):
        key = EG_generate_keys()
        (u, U) = key

        m1 = 1
        m2 = 0
        m3 = 1
        m4 = 1
        m5 = 0

        (r1, c1) = EGA_encrypt(m1, U)
        (r2, c2) = EGA_encrypt(m2, U)
        (r3, c3) = EGA_encrypt(m3, U)
        (r4, c4) = EGA_encrypt(m4, U)
        (r5, c5) = EGA_encrypt(m5, U)

        (r, c) = (r1*r2*r3*r4*r5, c1*c2*c3*c4*c5)

        m = bruteLog(PARAM_G, EG_decrypt(r, c, u), PARAM_P)
        m_it = m1+m2+m3+m4+m5

        self.assertEqual(m, m_it, 3)


if __name__ == '__main__':
    unittest.main()

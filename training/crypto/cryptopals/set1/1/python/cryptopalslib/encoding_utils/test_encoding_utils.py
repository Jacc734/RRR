from encoding_utils import EncodingUtilsClass as EncodingUtils
import unittest
import logging

logging.basicConfig()
logging.getLogger().setLevel(logging.DEBUG)


class TestEncodingUtilsClass(unittest.TestCase):

    def test_hex_string_to_byte_array(self):
        inp = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
        expected = bytearray('I\'m killing your brain like a poisonous mushroom')
        out = EncodingUtils.hex_string_to_byte_array(inp)
        self.assertEqual(out, expected)

    def test_byte_array_to_plain_string(self):
        inp = bytearray('I\'m killing your brain like a poisonous mushroom')
        expected = 'I\'m killing your brain like a poisonous mushroom'
        out = EncodingUtils.byte_array_to_plain_string(inp)
        self.assertEqual(out, expected)

    def test_byte_array_to_plain_string2(self):
        inp = bytearray([0x41, 0x42, 0x43])
        expected = 'ABC'
        out = EncodingUtils.byte_array_to_plain_string(inp)
        self.assertEqual(out, expected)

    def test_byte_array_to_hex_string(self):
        inp = bytearray('I\'m killing your brain like a poisonous mushroom')
        expected = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
        out = EncodingUtils.byte_array_to_hex_string(inp)
        self.assertEqual(out, expected)

    def test_plain_string_to_byte_array(self):
        inp = 'I\'m killing your brain like a poisonous mushroom'
        expected = bytearray('I\'m killing your brain like a poisonous mushroom')
        out = EncodingUtils.plain_string_to_byte_array(inp)
        self.assertEqual(out, expected)


if __name__ == '__main__':
    unittest.main()

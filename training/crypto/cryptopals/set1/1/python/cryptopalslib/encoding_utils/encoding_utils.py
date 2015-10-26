import logging
import binascii


class EncodingUtilsClass(object):

    @staticmethod
    def hex_string_to_byte_array(hex_string):
        byte_array = None
        try:
            byte_array = bytearray.fromhex(hex_string)
        except Exception as e:
            logging.error('Hex string could not be converted to byte array. Error: {0}'.format(e))
        return byte_array

    @staticmethod
    def byte_array_to_hex_string(byte_array):
        hex_string = ''
        try:
            hex_string = binascii.hexlify(byte_array)
            if type(hex_string) == bytes:  # for py3
                hex_string = hex_string.decode()
        except Exception as e:
            logging.error('Byte array could not be converted to hex string. Error: {0}'.format(e))
        return hex_string

    @staticmethod
    def byte_array_to_plain_string(byte_array):
        plain_string = ''
        try:
            plain_string = bytes(byte_array)
            if type(plain_string) == bytes:  # for py3
                hex_string = plain_string.decode()
        except Exception as e:
            logging.error('List of bytes could not be converted to plain string. Error: {0}'.format(e))
        return plain_string

    @staticmethod
    def plain_string_to_byte_array(plain_string):
        return bytearray(plain_string)


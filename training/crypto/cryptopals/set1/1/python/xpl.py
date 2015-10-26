#!/usr/bin/env python
from cryptopalslib.encoding_utils.encoding_utils import EncodingUtilsClass as EncodingUtils
from cryptopalslib.file_utils.file_utils import FileUtilsClass as FileUtils
import logging

logging.getLogger().setLevel(logging.DEBUG)

# remember to create the file with echo -n <string> > input.txt
inp = FileUtils.read_text_file('input.txt')
logging.info('Read file: {0}'.format(inp))
byte_array = EncodingUtils.hex_string_to_byte_array(inp)
logging.info('Byte Array: {0}'.format(byte_array))
b64string = EncodingUtils.byte_array_to_base64_string(byte_array)
logging.info('Base64 Encoded: {0}'.format(b64string))

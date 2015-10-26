from file_utils import FileUtilsClass as FileUtils
import unittest
import logging

logging.getLogger()

class TestStringMethods(unittest.TestCase):

    def test_write_and_read_file(self):
        inp = FileUtils.get_temp_file_name()
        expected = 'File Content'
        FileUtils.write_text_file(inp, expected)
        out = FileUtils.read_text_file(inp)
        self.assertEqual(out, expected)
        FileUtils.remove_file(inp)

    def test_remove_file(self):
        inp = FileUtils.get_temp_file_name()
        file_content = 'File Content'
        expected = True
        FileUtils.write_text_file(inp, file_content)
        out = FileUtils.remove_file(inp)
        self.assertEqual(out, expected)


if __name__ == '__main__':
    unittest.main()

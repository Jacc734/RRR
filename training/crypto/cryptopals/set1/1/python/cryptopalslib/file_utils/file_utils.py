import tempfile
import string
import random
import os
import logging


class FileUtilsClass(object):

    @staticmethod
    def read_text_file(file_path):
        file_content = None
        try:
            with open(file_path, 'rb') as fd:
                file_content = fd.read()
        except Exception as e:
            logging.error('File could not be read. Error: {0}'.format(e))
        return file_content

    @staticmethod
    def write_text_file(file_path, file_content):
        success = True
        try:
            with open(file_path, 'wb') as fd:
                fd.write(file_content)
        except Exception as e:
            logging.error('File could not be written. Error: {0}'.format(e))
            success = False
        return success

    @staticmethod
    def remove_file(file_path):
        success = True
        try:
            os.remove(file_path)
        except OSError as e:
            logging.error('File could not be removed. Error: {0}'.format(e))
            success = False
        return success

    @staticmethod
    def get_temp_file_name():
        tmp_dir = tempfile.gettempdir()
        filename = FileUtilsClass._get_random_string(10)
        return os.path.join(tmp_dir, filename)

    @staticmethod
    def _get_random_string(length):
        return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(length))



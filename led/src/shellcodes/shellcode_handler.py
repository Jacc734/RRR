#!/usr/bin/env python
#-*- coding: utf-8 -*-

from led.utils.file_utils import FileUtils
from led.utils.os_utils import OSUtils
from led.include.arg_values import ArgumentValues

class ShellcodeHandler(object):

    @staticmethod
    def handle(args):
        bin_sc = None
        c_sc_t = False
        sc_t_param = args[0]
        for sc_t in ArgumentValues.PAYLOAD_SHELLCODE:
            if sc_t == sc_t_param:
                c_sc_t = True
                break
        if c_sc_t:
            exist = OSUtils.check_folder('src/shellcodes/' + sc_t)
            if exist:
                fu = FileUtils('src/shellcodes/' + sc_t + '/shellcode.bin')
                bin_sc = fu.read_binary()
            else:
                print('Shellcode folder does not exist')
        else:
            print('Incorrect shellcode type')
        return bin_sc


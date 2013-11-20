#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
# FIXME: temporal fix until path correctly configured
import sys, os
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
from include.arg_values import ArgumentValues

class ArgUtils(object):

    def __init__(self):
        pass

    @staticmethod
    def parse_arguments():
        desc = '''
        The LED tool. The Lazy Exploit Developer tool at your service.
        '''
        epi = '\tCoded by newlog.\n\n'
        parser = argparse.ArgumentParser(
            description=desc,
            formatter_class=argparse.RawTextHelpFormatter,
            epilog=epi)
        parser.add_argument('--version', 
            action='version', 
            version='%(prog)s 0.1 alpha')
        parser.add_argument('-s', '--silent',
            default=argparse.SUPPRESS,
            action='store_true',
            help='Information messages not printed')

        subparsers = parser.add_subparsers(
            help='Several subcommands available')


        utils_parser = subparsers.add_parser('utils',
            help='''Several utilities at your service.\
                    \n\t-cp: create pattern.\n
                    \n\t-po: pattern offset.\n
                ''')
        utils_parser.add_argument('-cp', '--create_pattern',
            default=argparse.SUPPRESS,
            help='''
            Create a pattern.
            ''', 
            type=int,
            nargs=1)
        utils_parser.add_argument('-po', '--pattern_offset',
            default=argparse.SUPPRESS,
            help='''
            Get position in the pattern of the retrieved bytes.
            ''', 
            nargs=1)


        payloads_parser = subparsers.add_parser('payload',
            help='Several payload functionalities at your service.')
        """
        payloads_parser.add_argument('--silly_option',
            default=argparse.SUPPRESS,
            help='''
            Silly option for testing purposes.
            ''')
        """

        payloads_type_parser = payloads_parser.add_subparsers(dest='payload',
            help='Type of payload generation.')

        
        basic_payload_parser = payloads_type_parser.add_parser('basic',
            help='''
            Basic payload generation: [\\x90*nn][shellcode][ra*rn]
            '''
        )
        basic_payload_parser.add_argument('ret_addr',
            help='''
            Return address in hexadecimal form: 0xbfff1234
            ''')
        basic_payload_parser.add_argument('-st', '--shellcode_type',
            default=argparse.SUPPRESS,
            help='''
            Get position in the pattern of the retrieved bytes.
            ''', 
            nargs='+')
        basic_payload_parser.add_argument('-nn', '--nops_number',
            default=argparse.SUPPRESS,
            help='''
            Number of NOPs in the NOP Sled
            ''', 
            type=int,
            nargs=1)
        basic_payload_parser.add_argument('-rn', '--ret_number',
            default=[1],
            help='''
            Number of repetitions of the return address
            ''', 
            type=int,
            nargs=1)
       

        ret2libc_payload_parser = payloads_type_parser.add_parser('ret2libc',
            help='''
            Return to LIBC payload generation: [\\x90*nn][ra*rn][args]
            '''
        )
        ret2libc_payload_parser.add_argument('ret_addr',
            help='''
            Return address in hexadecimal form: 0xbfff1234
            ''')

        return parser.parse_args()


if __name__ == "__main__":

    args = ArgUtils.parse_arguments()
    print args


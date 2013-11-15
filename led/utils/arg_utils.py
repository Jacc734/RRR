#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse

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

        subparsers = parser.add_subparsers(
            help='Several subcommands available')


        utils_parser = subparsers.add_parser('utils',
            help='''Several utilities at your service.\
                    \n\t-cp: create pattern.
                ''')
        utils_parser.add_argument('-cp', '--create_pattern',
            help='''
            Create a pattern.
            ''', 
            nargs='+')
        utils_parser.add_argument('-po', '--pattern_offset',
            help='''
            Get position in the pattern of the retrieved bytes.
            ''', 
            nargs='+')


        payloads_parser = subparsers.add_parser('payload',
            help='Several payloads at your service.')
        payloads_parser.add_argument('-b', '--basic',
            help='''
            Basic payload.
            ''', 
            nargs='+')

        return parser.parse_args()

if __name__ == "__main__":

    args = ArgUtils.parse_arguments()
    print args


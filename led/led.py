#!/usr/bin/env python
# -*- coding: utf-8 -*-

from utils.arg_utils import ArgUtils
from libs.exploit_utils import ExploitUtils

if __name__ == '__main__':

    args = ArgUtils.parse_arguments()
    args = vars(args)
    if args.get('create_pattern'):
        sub_args = args.get('create_pattern')
        print ExploitUtils.create_pattern(int(sub_args[0]))
    if args.get('pattern_offset'):
        sub_args = args.get('pattern_offset')
        print ExploitUtils.pattern_offset(sub_args[0])
    if args.get('payload'):
        sub_args = args.get('paylaod')
        print ExploitUtils.gen_payload(sub_args[0])


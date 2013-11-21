#!/usr/bin/env python
# -*- coding: utf-8 -*-

from utils.arg_utils import ArgUtils
from utils.utils import Utils
from utils.exploit_utils import ExploitUtils
from payloads.basic_stack import BasicStack
from payloads.ret2libc import Ret2Libc
from payloads.format_string import FormatString
from payloads.rop import Rop

if __name__ == '__main__':

    args = ArgUtils.parse_arguments()
    args = vars(args)
    print args
    # TODO: First we have to process the general options such as -silent
    # and remove them from the argument list
    if args['functionality'] == 'util':
        if 'create_pattern' in args:
            print ExploitUtils.create_pattern(args)
        if 'pattern_offset' in args:
            print ExploitUtils.pattern_offset(args)
        else:
            print("Parameter not recognized")
    elif args['functionality'] == 'payload':
        pay_type = args['payload']
        if pay_type == 'basic': 
            print BasicStack.payload(args)
        elif pay_type == 'ret2libc': 
            print Ret2Libc.payload(args)
        elif pay_type == 'frmtstr': 
            print FormatString.payload(args)
        elif pay_type == 'rop': 
            print Rop.payload(args)
        else:
            print("Payload type not recognized")


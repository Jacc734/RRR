#/usr/bin/env python
#-*- coding: utf-8 -*-

class ArgumentValues(object):

    ##################
    #  UTILS MODULE  #
    ##################



    ##################
    # PAYLOAD MODULE #
    ##################

    PAYLOAD_TYPE =     [
                            'basic',
                            'ret2libc',
                            'rop'
    ]
    PAYLOAD_SHELLCODE = [
                            'execve',
                            'bind',
                            'reverse'
    ]


#!/usr/bin/env python
#-*- coding: utf-8 -*-

class Utils(object):

    @staticmethod
    def addr_to_byte(addr, bo='be'):
        '''
        Convert a string hex byte values into a byte string.
        '0x41424344' -> 'ABCD'
        '0x41424344' -> '\x41\x42\x43\x44'
        '''
        res = None
        if addr:
            if addr.startswith('0x'):
                addr = addr.lstrip('0x')
            if len(addr) % 2 == 0:
                try:
                    res_list = []
                    for i in range(0, len(addr), 2):
                        res_list.append(chr(int(addr[i:i+2], 16 ) ) )
                    res = ''.join(res_list)
                    if bo == 'le':
                        res = res[::-1]
                except ValueError as e:
                    print("Error parsing addr - 0x value not hex: {0}".format(e))
        return res 

    @staticmethod
    def byte_to_addr(addr, bo='be'):
        res = None
        if addr:
            if bo == 'le':
                addr = addr[::-1]
            if len(addr) % 2 == 0:
                res = ''.join('{0:x}'.format(ord(b)) for b in addr if b != 'u')
                res = '0x' + res
        return res

if '__name__' == '__main__':
    pass

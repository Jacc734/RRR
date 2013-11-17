#!/usr/bin/env python

class Utils(object):

    @staticmethod
    def addr_to_ascii(addr):
        res = None
        if addr and addr.startswith('0x'):
            addr = addr.lstrip('0x')
        else:
            return res
        try:
            if len(addr) == 8:
                res = "".join(
                    chr(int(addr[0]+addr[1], 16)) +
                    chr(int(addr[2]+addr[3], 16)) +
                    chr(int(addr[4]+addr[5], 16)) +
                    chr(int(addr[6]+addr[7], 16))
                    )
            elif len(addr) == 16:
                res = "".join(
                    chr(int(addr[0]+addr[1], 16)) +
                    chr(int(addr[2]+addr[3], 16)) +
                    chr(int(addr[4]+addr[5], 16)) +
                    chr(int(addr[6]+addr[7], 16)) +
                    chr(int(addr[8]+addr[9], 16)) +
                    chr(int(addr[10]+addr[11], 16)) +
                    chr(int(addr[12]+addr[13], 16)) +
                    chr(int(addr[14]+addr[15], 16))
                    )
            else:
                print("arch not supported")
        except ValueError as e:
            print("Error parsing addr - 0x value not hex: {0}".format(e))

        return res

if '__name__' == '__main__':
    pass

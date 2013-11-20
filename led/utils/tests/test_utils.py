#!/usr/bin/env python
import unittest

import sys, os
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
from utils import Utils

# Execute 'python -m unittest discover -v' to execute all tests from project

class TestUtils(unittest.TestCase):

    def test_addr_to_byte__generic(self):
        addr = '0x41424344'
        addr = Utils.addr_to_byte(addr, bo='le')
        self.assertEqual(addr, 'DCBA')
        self.assertEqual(addr, '\x44\x43\x42\x41')
        
        addr = '41424344'
        addr = Utils.addr_to_byte(addr, bo='le')
        self.assertEqual(addr, 'DCBA')
        self.assertEqual(addr, '\x44\x43\x42\x41')
        
        addr = '0x4142434461626364'
        addr = Utils.addr_to_byte(addr)
        self.assertEqual(addr, 'ABCDabcd')
        self.assertEqual(addr, '\x41\x42\x43\x44\x61\x62\x63\x64')

        addr = '0x4142434445464748'
        addr = Utils.addr_to_byte(addr, bo='le')
        self.assertEqual(addr, '\x48\x47\x46\x45\x44\x43\x42\x41')

        addr = '0x414243440' # invalid addr length
        addr = Utils.addr_to_byte(addr)
        self.assertEqual(addr, None)
        
        addr = '0x4142434u' # invalid addr value
        addr = Utils.addr_to_byte(addr)
        self.assertEqual(addr, None)
    
    def test_byte_to_addr__generic(self):
        addr = 'ABCD'
        addr = Utils.byte_to_addr(addr)
        self.assertEqual(addr, '0x41424344')
        
        addr = 'DCBA'
        addr = Utils.byte_to_addr(addr, bo='le')
        self.assertEqual(addr, '0x41424344')
        
        addr = 'ABCDabcd'
        addr = Utils.byte_to_addr(addr)
        self.assertEqual(addr, '0x4142434461626364')

        addr = '\x48\x47\x46\x45\x44\x43\x42\x41'
        addr = Utils.byte_to_addr(addr, bo='le')
        self.assertEqual(addr, '0x4142434445464748')

        addr = '414243440' # invalid addr length
        addr = Utils.byte_to_addr(addr)
        self.assertEqual(addr, None)
        # byte_to_addr does not check if addr value is correct
        #addr = '4142434u' # invalid addr value
        #addr = Utils.byte_to_addr(addr)
        #self.assertEqual(addr, None)

if __name__ == '__main__':
    unittest.main()

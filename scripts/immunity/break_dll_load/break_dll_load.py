#!/usr/bin/env python
from immlib import LoadDLLHook, Debugger


class DLLHook(LoadDLLHook):

    imm = Debugger()

    def __init__(self, modulenames, addresses):
        LoadDLLHook.__init__(self)
        self.modulenames = modulenames
        self.addrs = addresses

    def run(self, regs):
        for module in self.modulenames:
            if module in self.imm.getAllModules().keys():
                # set breakpoint
                index = self.modulenames.index(module)
                self.imm.setBreakpoint(self.addrs[index])
                self.modulenames.remove(module)
                self.imm.log('[+] Breakpoint set in 0x%x' % self.addrs[index])
                # unhook
                if not self.modulenames:
                    self.disable()
                    self.UnHook()


def main(args):
    modulenames, addresses = parse_args(args)
    if modulenames and addresses:
        ret = '[+] Module loaded. Will break on: {0}'.format(zip(modulenames, addresses))
        hook = DLLHook(modulenames, addresses)
        hook.add('dll_hooker')
    else:
        imm = Debugger()
        ret = '[-] Incorrect arguments. Usage: <script> mod1,mod2 0x1234,0x4321'
        imm.log(ret)

    return ret


def parse_args(args):
    modulenames = None
    addresses = None
    if args and len(args) == 2:
        if ',' in args[0]:
            modulenames = args[0].split(',')
        else:
            modulenames = []
            modulenames.append(args[0])
        if ',' in args[1]:
            addresses = args[1].split(',')
            addresses = [int(addr, 16) for addr in addresses]
        else:
            addresses = []
            addresses.append(int(args[1], 16))
    if len(modulenames) != len(addresses):
        modulenames = None
        addresses = None

    return modulenames, addresses

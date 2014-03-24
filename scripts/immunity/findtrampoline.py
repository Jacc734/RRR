#!/usr/bin/env python

from immlib import *
from copy import deepcopy
import struct
import random

SEP = ";"
IP_REG = "EIP" # TODO: This depends on arch (x86, x64)
PRINT_INST = 0
DEFAULT_DEPTH = 20
DEFAULT_PRINT_ALL = False
INSTS = [
            "jmp *reg*",
            "call *reg*",
            "push *reg*;ret"
]

def usage(imm):
    imm.log("[-] No arguments found. ")
    imm.log("[*] You should pass the registers you control separated by spaces.")
    imm.log("[*] With two optional parameters:")
    imm.log("[*] -> depth parameter (def. 20): # of instructions to search from crash point.")
    imm.log("[*] -> print_all parameter (def. false): determines if all flows from instructions already reported should be printed.")
    imm.log("[*] !pycommand eax ebx esi 20 false")

def replace_inst(reg):
    tmp = [inst.replace("*reg*", reg) for inst in INSTS]
    return [inst.replace(";", "\n") for inst in tmp]

def store_insts(imm, registers):
    imm.setStatusBar("Searching instructions...")
    hit_addrs = {} # using a dict because search is O(1) and can keep track of addr <-> inst
    for reg in registers:
        instructions = replace_inst(reg)
        for inst in instructions:
            printable_inst = inst.replace("\n", SEP)
            imm.log("[+] Searching for instruction {0}".format(printable_inst))
            opcode = imm.assemble(inst)
            found_addrs = imm.search(opcode)
            for hit in found_addrs:
                imm.log("[+] Opcode for instruction <{0}> found in: 0x{1:x}".format(printable_inst, hit))
                hit_addrs[hit] = printable_inst
    return hit_addrs

def check_addr_perms(imm, ip):
    success = True
    page = imm.getMemoryPageByAddress(ip)
    if page:
        access = page.getAccess(human=True)
        if not access or "PAGE_NOACCESS" == access: # usually, access=PAGE_EXECUTE_READ
            imm.log("[-] Incorrect permissions for address: 0x{0:0x}".format(ip))
            success = False
    else:
        imm.log("[-] Something went wrong obtaining page from address: 0x{0:0x}".format(ip))
        imm.log("[-] Probably IP is null. This might happen because a jmp/call reg is found and reg=0")
        imm.log("[-] Cutting this code branch.")
        success = False
    return success

def traverse_code(imm, ip, depth, flow=[], final=[]): # remember that final is modified by reference ;)
    #imm.log("[+] IP: 0x{0:0x}".format(ip))
    #imm.log("[+] depth: {0}".format(depth))
    #imm.log("[+] flow: {0}".format(flow))
    #imm.log("[+] final: {0}".format(final))
    if check_addr_perms(imm, ip):
            op = imm.disasm(ip)
            printable_inst = op.getResult()
            # a list to keep inst. order and a dict to add more attributes to instruction addresses (keys)
            flow.append({ip : [printable_inst]})
            depth -= 1
    else:
        depth = 0
    if depth == 0:
        final.append(flow)
    else:
        if op.isCall() or op.isJmp() or op.isConditionalJmp():
            deepcopy(flow)
            traverse_code(imm, op.getJmpAddr(), depth, deepcopy(flow), final)
        ip += op.getSize()
        traverse_code(imm, ip, depth, deepcopy(flow), final)
    return final # result for the caller out of the recursive cycle

def main(args):
    ret = "[*] PyCommand executed."
    imm = Debugger()
    # TODO: replace this shit using argparse lib
    if not args:
        usage(imm)
        return ret

    registers, depth, print_all_found_flows = parse_arguments(args)

    imm.log("[+] Registers in control: {0}".format(registers))
    imm.log("[+] Depth set to {0}".format(depth))

    found_insts = store_insts(imm, registers)
    
    regs = imm.getRegs()
    ip = regs[IP_REG]
    imm.log("[+] Examining code flow from 0x{0:x}".format(ip))
    print_warning(imm)
    results = traverse_code(imm, ip, depth)
    imm.log("[+] Code traversed.")
    
    if results:
        imm.setStatusBar("Writing results...")
        write_flows_to_file(results)
        rnd_str = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(5))
        already_written = set() # order does not matter, performance does
        found = False
        for flow in results:
            for inst in flow:
                inst_addr = inst.keys()[0]
                if inst_addr in found_insts:
                    found = True
                    if print_all_found_flows == True:
                        imm.log("[+] JACKPOT, TRAMPOLINE FOUND.")
                        imm.log("[+] FOUND INSTRUCTION: {0}".format(inst[inst_addr][PRINT_INST]))
                        write_winner_flow(imm, flow, inst_addr, rnd=rnd_str)
                    else:
                        if not inst_addr in already_written:
                            write_winner_flow(imm, flow, inst_addr, rnd=rnd_str)
                            already_written.add(inst_addr)
        if not found:
            imm.log("[-] No results found. Try to increase depth parameter value. depth={0}".format(depth)) 
    else:
        imm.log("[-] Something went wrong. Code could not be traversed.")
    
    return ret

def parse_arguments(args):
    possible_optional = args[-2:]
    found_print_all = False
    if "true" in possible_optional:
        print_all_found_flows = True
        found_print_all = False
    elif "false" in possible_optional:
        print_all_found_flows = False
        found_print_all = False
    else:
        print_all_found_flows = DEFAULT_PRINT_ALL
    found_depth = False
    for arg in possible_optional:
        if arg.isdigit():
            found_depth = True
            depth = int(arg)
    if not found_depth:
        depth = DEFAULT_DEPTH
    if found_depth:
        args.pop()
    if found_print_all:
        args.pop()

    return args, depth, print_all_found_flows

def write_winner_flow(imm, flow, hit_addr, to=2, rnd=None):
    if to == 0:
        write_winner_flow_to_screen(imm, flow, hit_addr)
    elif to == 1:
        write_winner_flow_to_file(imm, flow, hit_addr, rnd)
    elif to == 2:
        write_winner_flow_to_screen(imm, flow, hit_addr)
        write_winner_flow_to_file(imm, flow, hit_addr, rnd)

def write_winner_flow_to_file(imm, flow, hit_addr, rnd):
    if not rnd:
        rnd = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(5))
    filename = "winner_flow_" 
    filename += rnd
    filename += ".txt"
    with open(filename, "a") as fd:
        fd.write("------------\n")
        for inst in flow:
            inst_addr = inst.keys()[0]
            if inst_addr != hit_addr:
                fd.write("0x{0:0x}: {1}\n".format(inst_addr, inst[inst_addr][PRINT_INST]))
            else:
                fd.write("0x{0:0x}: --> {1} <--\n".format(inst_addr, inst[inst_addr][PRINT_INST]))
        fd.write("------------\n")

def write_winner_flow_to_screen(imm, flow, hit_addr):
    imm.log("------------")
    for inst in flow:
        inst_addr = inst.keys()[0]
        if inst_addr != hit_addr:
            imm.log("0x{0:0x}: {1}".format(inst_addr, inst[inst_addr][PRINT_INST]))
        else:
            imm.log("0x{0:0x}: --> {1} <--".format(inst_addr, inst[inst_addr][PRINT_INST]))
    imm.log("------------")

def write_flows_to_file(flows):
    filename="code_flows.txt"
    with open(filename, "w") as fd:
        for flow in flows:
            for inst in flow:
                fd.write("{0}\n".format(inst))
            fd.write("------------\n")

def print_warning(imm):
    imm.log("[+] WARNING:") 
    imm.log("You have to understand that if jmp/call reg are found, ")
    imm.log("their computed jump address most probably won't be correct, ")
    imm.log("because code is not eventually executed so register values are not real, ")
    imm.log("but those when stored when the script is launched.")


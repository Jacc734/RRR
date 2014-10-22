import my_debugger

debugger = my_debugger.debugger()

pid = raw_input("[+] Enter the PID of the process to attach to: ")

debugger.attach(int(pid))
"""
# Setting a soft breakpoint in printf
printf_address = debugger.func_resolve("msvcrt.dll", "printf")
print "[*] Address of printf: 0x%08x" % printf_address
if not debugger.bp_set(printf_address):
	print "[-] Breakpoint not set. Detaching process and exiting..."
	debugger.detach()
	exit(0)
"""
"""
# Setting a hardware breakpoint in printf
printf_address = debugger.func_resolve("msvcrt.dll", "printf")
print "[*] Address of printf: 0x%08x" % printf_address
from my_debugger_defines import *
if not debugger.bp_set_hw(printf_address, 1, HW_EXECUTE):
	print "[-] Breakpoint not set. Detaching process and exiting..."
	debugger.detach()
	exit(0)
"""
"""
# Setting a hardware breakpoint in printf
printf_address = debugger.func_resolve("msvcrt.dll", "printf")
print "[*] Address of printf: 0x%08x" % printf_address
from my_debugger_defines import *
if not debugger.bp_set_mem(printf_address, 1):
	print "[-] Breakpoint not set. Detaching process and exiting..."
	debugger.detach()
	exit(0)
"""
debugger.run()
debugger.detach()
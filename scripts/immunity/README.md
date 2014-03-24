findtrampoline Immunity Debugger Plugin
=======================================

This Immunity extension is thought to be used for exploiting purposes. If you
find any other use for it, be my guest :)

Sometimes you will crash an application but you won't control any flow changer
variable such as eip or a seh chain. You might only control any of the other
registers. In those cases, you have to manually search for trampolines that let
you jump to the address stored by those registers. 

For example, once the program has crashed, if you only control the eax register
value you will put a controlled address in the register and then search for
instructions such as jmp eax, call eax or push eax;ret. This plugin searches
for this kind of instructions from the point in which the application crashed
until a configurable depth, traversing all the possible flows, following jumps
and calls. Then if a valuable instruction is found, the plugin will show you
the execution flow that has followed in order to get to that instruction.

Plugin Setup
------------

You only have to download the findtrampoline.py file and store it in the
PyCommands directory from the Immunity Debugger folder. No dependencies.

Plugin Usage
------------

As with all Immunity PyCommands, you execute this script from the immunity
command line interface. Is as simple as calling the script passing the
registers you control separed by spaces.

    $ !findtrampoline eax ebx

You can also specify two optional commands that must be placed as the last
parameters. 
The `depth` parameter and the `print_all_flows` parameter.

The depth parameter specifies the number of assembler instructions that will be
read from the IP (instruction pointer) register address. For example, if
depth=20, 20 instructions will be read from the IP address following all the
code flow path, so you will have n flows with 20 instructions each. Its default
value is 20.

The print_all_flows parameter must be set to true or false. When executing this
command, it is highly probable that one same instruction is found going through
different code flows. For example, you can reach a "jmp reg" instruction in
address X going through different code paths.
Setting this parameter to true will print as a result the same found
instruction showing all the code paths that have reached it. If this parameter
is set to false, if an instruction has already been reported with one code
path, it will not be reported again with a different code path. 
The recommended value for this parameter is false, an so is its default value.
Setting it to true might cause the output to be huge.

Examples of its use follows:

    $ !findtrampoline eax ebx 10 false

    $ !findtrampoline esi 10

    $ !findtrampoline esi true

Results
-------

Once the command is executed, the results will be printed in the Immunity
Log view and will also be written to a file. This file will be stored in the
Immunity Debugger directory with "winner_flow_`<nonce>`.txt" as name. If you want
to know which is the last result, order the files by modified date!

The result is the trampoline instruction found and the code path followed to 
reach it.

An example of its output, executing `!findtrampoline eax 30` follows:

```
------------
0x1d0012a8: CALL python.1D001628
0x1d0012ad: JMP python.1D001051
0x1d0012b2: MOV EDI,EDI
0x1d0012b4: PUSH EBP
0x1d0012b5: MOV EBP,ESP
0x1d0012b7: MOV EAX,DWORD PTR SS:[EBP+8]
0x1d0012ba: MOV EAX,DWORD PTR DS:[EAX]
0x1d0012bc: CMP DWORD PTR DS:[EAX],E06D7363
0x1d0012c2: JNZ SHORT python.1D0012EE
0x1d0012c4: CMP DWORD PTR DS:[EAX+10],3
0x1d0012c8: JNZ SHORT python.1D0012EE
0x1d0012ca: MOV EAX,DWORD PTR DS:[EAX+14]
0x1d0012cd: CMP EAX,19930520
0x1d0012d2: JE SHORT python.1D0012E9
0x1d0012e9: CALL <JMP.&MSVCR90.?terminate@@YAXXZ>
0x1d0016be: JMP DWORD PTR DS:[<&MSVCR90.?terminate@@YAXXZ>]
0x747fbe7b: PUSH 8
0x747fbe7d: PUSH MSVCR90.7482D180
0x747fbe82: CALL MSVCR90.7480CF00
0x747fbe87: CALL MSVCR90._getptd
0x747fbe8c: MOV EAX,DWORD PTR DS:[EAX+78]
0x747fbe8f: TEST EAX,EAX
0x747fbe91: JE SHORT MSVCR90.747FBEA9
0x747fbe93: AND DWORD PTR SS:[EBP-4],0
0x747fbe97: --> CALL EAX <--
------------
```

This output means that from IP=0x1d0012a8 you have found two trampolines using
registear eax 30 instructions away at most from IP.

Known limitations
----------------

There are some bugs you must be aware of. When the code path is searched, the 
instructions are not executed. The program crashed, remember? This means that 
if a "code flow modifier instruction" (i.e jmps, calls, rets) depends on the 
value of a register, the destination address will most probably be wrong.

Return instructions won't be correctly computed, so instead of "interpreting"
the ret instruction, the script will process the next instruction.

For this reason, this script is thought to be executed with a low depth, such 
as 10, 15 or 20 depending on the point in which the program has crashed. 
Increasing depth will make the results to be less reliable.

To sum up, with this script you can save 20 minutes of your time and easily 
get an idea of the surroundings from your crash point.

These bugs perhaps could be solved by virtually executing instructions after 
the crash point. If you want to try it, be my guest :) 

License
-------

This code is licensed under the WTFPL v2.0. More information about this license
can be found [here](http://es.wikipedia.org/wiki/WTFPL) and [here](https://tldrlegal.com/license/do-wtf-you-want-to-public-license-v2-(wtfpl-2.0)).
A quick summary of the license would be Do What The Fuck You Want To.


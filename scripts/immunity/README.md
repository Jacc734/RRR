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

```
$ !findtrampoline eax ebx```

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

```
$ !findtrampoline eax ebx 10 false```

```
$ !findtrampoline esi 10```

```
$ !findtrampoline esi true```

Results
-------

Once the command is executed, the results will be printed in the Immunity
Log view and will also be written to a file. This file will be stored in the
Immunity Debugger directory with "winner_flow_<nonce>.txt" as name. If you want
to know which is the last result, order the files by modified date!

The result is the trampoline instruction found and the code path followed to 
reach it.

License
-------

This code is licensed under the WTFPL v2.0. More information about this license
can be found [here](http://es.wikipedia.org/wiki/WTFPL) and [here](https://tldrlegal.com/license/do-wtf-you-want-to-public-license-v2-(wtfpl-2.0)).
A quick summary of the license would be Do What The Fuck You Want To.


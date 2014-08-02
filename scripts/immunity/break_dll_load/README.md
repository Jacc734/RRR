break_dll_load Immunity Debugger Plugin
=======================================

This Immunity extension is thought to be used for exploiting purposes, but can
perfectly fit if you are analyzing malware. If you find any other use for it, 
be my guest :)

Sometimes DLL are not loaded at software startup but are loaded dynamically
once the application is running. This plugin monitors all DLL loading actions
and checks if a particular DLL is loaded. If so, it will add a breakpoint in
the desired address.  

I use this plugin in the following scenario. You are exploiting a binary
throught SEH overwriting. You choose to overwrite a SEH Handler with a 
POP/POP/RET gadget from a certain DLL. What happens if you want to place a
breakpoint in the address of that gadget but the DLL is not loaded at startup?
You'd have to follow all the execution flow until that point and then set the
breakpoint. With this plugin you can say: "Once the DLL is loaded, set the
breakpoint in that address". Useful, isn't it?

Of course, this is just one possible scenario. Sure you can find many more use
cases.

Plugin Setup
------------

You only have to download the findtrampoline.py file and store it in the
PyCommands directory from the Immunity Debugger folder. No dependencies.

Plugin Usage
------------

As with all Immunity PyCommands, you execute this script from the immunity
command line interface. Is as simple as calling the script passing the
module loads you want to track and the address in which you want to set the
breakpoints.

    $ !break_dll_load module1.dll,module2.dll 0xDEADBEEF,0xBADF00D

This means that once `module1.dll` is loaded a breakpoint will be set in
address `0xDEADBEEF` and when `module2.dll` is loaded a breakpoint in `0xBADF00D`
will be set. The order is not significant. 

Usually, in the context of a SEH overwrite, address `0xDEADBEEF` would pertain
to `module1.dll` and address `0xBADF00D` would pertain to `module2.dll`.

It's important to understand that the plugin will pair module and address
depending of their position in the arguments. So first module will be paired
with first address and so on.

Addresses must be set in hexadecimal, with or without the '0x'. Module search
is case sensitive to speed a little more the search. Remember to add the '.dll'.

Results
-------

You will see how the breakpoint is set in the Immunity Debugger Breakpoint
Window.

License
-------

This code is licensed under the WTFPL v2.0. More information about this license
can be found [here](http://es.wikipedia.org/wiki/WTFPL) and [here](https://tldrlegal.com/license/do-wtf-you-want-to-public-license-v2-(wtfpl-2.0)).
A quick summary of the license would be Do What The Fuck You Want To.


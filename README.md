# RRR
Right Registers Registry - Correct Registers Registry


    RRR will mitigate errors that are contained in return instructions. These errors will appear for several reasons. After the initial program crash, if a return is depending on a register value or calculations in instructions affecting the return value. In this case, the program will check for register values that are updated and execute the calculation in an attempt to keep the register updated after the crash.
    
    This is high-level diagram of the program and how it will operate. This will represent both FindTrampoline and the RRR extension (since RRR will be the name of this fork for FindTrampoline, due with the additional changes added internally).

# rrr
right registers registry - Correct registers registry extension to findtrampoline

    RRR will attempt to mitigate errors that are contained in return instructions.
	After the initial program crash, if a return is depending on a register value or calculations in instructions affecting the return value. 
	In this case, the rrr extension will check for register values that are updated and execute the calculation in an attempt to keep returns accurate, even after a crash.
from ctypes import *
import time

msvcrt = cdll.msvcrt

def func(arg1):
	msvcrt.printf("Inside function! Arg: %s\n" % arg1)

counter = 0

while counter < 10:
	msvcrt.printf("Loop iteration %d!\n" % counter)
	time.sleep(2)
	counter += 1
func("Hello!")
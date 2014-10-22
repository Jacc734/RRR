
from ctypes import *
from my_debugger_defines import *

kernel32 = windll.kernel32

class debugger():

	def __init__(self):
		self.h_process			= None
		self.pid 				= None
		self.debugger_active	= None
		self.h_thread 			= None
		self.context 			= None
		self.exception 			= None
		self.exception_address 	= None
		self.breakpoints		= {}
		self.first_breakpoint 	= True
		self.hardware_breakpoints = {}
		self.guarded_pages 		= []
		self.memory_breakpoints = {}

		# Get the default page size
		system_info = SYSTEM_INFO()
		kernel32.GetSystemInfo(byref(system_info))
		self.page_size = system_info.dwPageSize


	def load(self, path_to_exe):

		#print "Executing load()"

		print "[*] We have successfully launched the process!"
		print "[*] PID: %d" % process_information.dwProcessId

		# Obtain a valid handle to the newly created process
		# and store it for future access
		self.h_process = self.open_process(process_information.dwProcessId)

	def open_process(self, pid):
		
		#print "Executing open_process()"
		
		h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
		return h_process

	def attach(self, pid):

		#print "Executing attach()"

		self.h_process = self.open_process(pid)

		# We attempt to attach the process
		# if this fails we exit the call
		if kernel32.DebugActiveProcess(pid):
			self.debugger_active = True
			self.pid = int(pid)
		else:
			print "[*] Unable to attach to the process."

	def run(self):

		#print "Executing run()"

		# Now we have to poll the debugee for 
		# debugging events
		while self.debugger_active == True:
			self.get_debug_event()

	def get_debug_event(self):

		#print "Executing get_debug_event()"

		debug_event = DEBUG_EVENT()
		continue_status = DBG_CONTINUE

		if kernel32.WaitForDebugEvent(byref(debug_event), 100):
			# Obtain the thread and context information
			self.h_thread = self.open_thread(debug_event.dwThreadId)
			self.context = self.get_thread_context(h_thread=self.h_thread)

			print "Event Code: %d Thread ID: %d" % (debug_event.dwDebugEventCode, debug_event.dwThreadId)

			# EXCEPTION_DEBUG_EVENT is a windows-driven breakpoint always executed to allow a debugger
			# to inspect the process's state before resuming execution
			if debug_event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT: # If the event code is an exception...
				# Obtain the exception code
				exception = debug_event.u.Exception.ExceptionRecord.ExceptionCode
				self.exception_address = debug_event.u.Exception.ExceptionRecord.ExceptionAddress

				if exception == EXCEPTION_ACCESS_VIOLATION:
					print "Access violation detected."
				elif exception == EXCEPTION_BREAKPOINT: # Soft breakpoint
					continue_status = self.exception_handler_breakpoint()
				elif exception == EXCEPTION_GUARD_PAGE:	# Memory breakpoint
					continue_status = self.exception_handler_guard_page()
				elif exception == EXCEPTION_SINGLE_STEP: # Hardware breakpoint
					continue_status = self.exception_handler_single_step()

			kernel32.ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, continue_status)

	def detach(self):

		#print "Executing deattach()"

		if kernel32.DebugActiveProcessStop(self.pid):
			print "[*] Finished debugging. Exiting..."
			return True
		else:
			return False

	def open_thread(self, thread_id):

		#print "Executing open_thread()"

		h_thread = kernel32.OpenThread(THREAD_ALL_ACCESS, None, thread_id)
		if h_thread is not None:
			return h_thread
		else:
			print "[*] Could not obtain a valid handle."
			return False

	def enumerate_threads(self):

		#print "Executing enumerate_threads()"

		# You can not obtain the threads of one specific PID,
		# you obtain all the threads and select those with the required PID

		thread_entry = THREADENTRY32()
		thread_list = []
		# The PID is not used for TH32CS_SNAPTHREAD
		snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, self.pid)

		if snapshot is not None:
			# You have to set the size of the struct or the call will fail
			thread_entry.dwSize = sizeof(thread_entry)
			success = kernel32.Thread32First(snapshot, byref(thread_entry))

			i = 0
			while success:
				if thread_entry.th32OwnerProcessID == self.pid:
					thread_list.append(thread_entry.th32ThreadID) # store thread id

				success = kernel32.Thread32Next(snapshot, byref(thread_entry))

			kernel32.CloseHandle(snapshot)
			return thread_list
		else:
			return False

	def get_thread_context(self, thread_id=None, h_thread=None):

		#print "Executing get_thread_context()"
		if not (thread_id or h_thread):
			print "[-] Exception received without enough data. thread_id or handle h_thread must be specified."
			print "[?] You might have tried to end debugged process without stopping debugger. Close debugger first."
			return False

		context = CONTEXT()
		context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS

		# Obtain handle to the thread
		if thread_id and not h_thread:
			self.h_thread = self.open_thread(thread_id)
		if kernel32.GetThreadContext(self.h_thread, byref(context)):
			return context
		else:
			return False

	def exception_handler_breakpoint(self): # Software breakpoint (INT3)

		print "[*] Soft breakpoint exception address: 0x%08x" % self.exception_address
		# check if the breakpoint is one that we set, if not, it is a Windows default breakpoint
		if not self.breakpoints.has_key(self.exception_address):

			# if it is the first Windows driven breakpoint
			# then let's just continue on
			if self.first_breakpoint == True:
				self.first_breakpoint = False
				print "[*] Hit the first breakpoint."
		else:
			print "[*] Hit user defined breakpoint."

			# obtain a fresh context record, reset EIP back to the 
			# original byte and then set the thread's context record
			# with the new EIP value
			self.context = self.get_thread_context(h_thread=self.h_thread)
			self.context.Eip -= 1
			kernel32.SetThreadContext(self.h_thread,byref(self.context))
			
			self.display_context()
			self.ask(bk_type="s")

		continue_status = DBG_CONTINUE

		return continue_status

	def exception_handler_single_step(self): # Hardware breakpoint (INT1)

		print "[*] Hardware breakpoint exception address: 0x%08x" % self.exception_address

		# Check if this signal (INT1) ocurred in reaction to a hw breakpoint and
		# grab it. According to intel docs, we should be able to check the BS flag
		# in Dr6, but it appears that Win is not propagating the flag down to us
		continue_status = DBG_CONTINUE
		if self.context.Dr6 & 0x1 and self.hardware_breakpoints.has_key(0):
			slot = 0
		elif self.context.Dr6 & 0x2 and self.hardware_breakpoints.has_key(1):
			slot = 1
		elif self.context.Dr6 & 0x4 and self.hardware_breakpoints.has_key(2):
			slot = 2
		elif self.context.Dr6 & 0x8 and self.hardware_breakpoints.has_key(3):
			slot = 3
		else:
			# This was not an INT1 generated by a hw breakpoint
			print "[-] Hardware breakpoint found, but not set by the user."
			continue_status = DBG_EXCEPTION_NOT_HANDLED

		print "[*] Hit user defined breakpoint."
		
		self.display_context()
		self.ask(bk_type="h", slot=slot)
		
		return continue_status

	def exception_handler_guard_page(self): # Memory breakpoint (PAGE_GUARD exception)

		print "[*] Memory breakpoint exception address: 0x%08x" % self.exception_address

		if self.memory_breakpoints.has_key(self.exception_address):
			print "[*] Hit user defined breakpoint." 
			self.display_context()
			size = self.memory_breakpoints[self.exception_address][1]
			print "SIZE = %d" % size
			self.ask(bk_type="m", size=size)
			continue_status = DBG_CONTINUE
		else:
			print "[-] Hardware breakpoint found, but not set by the user."
			continue_status = DBG_EXCEPTION_NOT_HANDLED
		
		return continue_status

	def read_process_memory(self, address, length):

		data = ""
		read_buf = create_string_buffer(length)
		count = c_ulong(0)

		if kernel32.ReadProcessMemory(self.h_process, address, read_buf, length, byref(count)):
			data += read_buf.raw
			return data
		else:
			return False
	
	def write_process_memory(self, address, data):

		count = c_ulong(0)
		length = len(data)
		c_data = c_char_p(data[count.value:])

		if kernel32.WriteProcessMemory(self.h_process, address, c_data, length, byref(count)):
			return True
		else:
			return False

	def bp_set(self, address): # Set a soft breakpoint

		if not self.breakpoints.has_key(address):
			try:
				#old_protect = c_ulong(0)
				#if not kernel32.VirtualProtectEx(self.h_process, address, 1, PAGE_EXECUTE_READWRITE, byref(old_protect)):
				#	print "[-] Memory permissions could not be changed."
				# Store the original byte
				original_byte = self.read_process_memory(address, 1)
				if original_byte != False:
					# Write the INT3 opcode
					if self.write_process_memory(address, "\xCC"):
						# Register the breakpoint
						self.breakpoints[address] = (original_byte)
						print "[*] Breakpoint set at address 0x%08x" % address
						return True
			except Exception as e:
				print "[-] Something went wrong setting the soft breakpoint.", e
				return False

	def func_resolve(self, dll, function): # Get the address of function for the given dll 

		handle = kernel32.GetModuleHandleA(dll)
		address = kernel32.GetProcAddress(handle, function)

		kernel32.CloseHandle(handle)

		return address

	def bp_set_hw(self, address, length, condition):

		# Check for a valid length value
		if length not in (1, 2, 4):
			return False
		else:
			length -= 1

		# Check for a valid condition
		if condition not in (HW_ACCESS, HW_EXECUTE, HW_WRITE):
			return False

		# Check for available slots
		if not self.hardware_breakpoints.has_key(0):
			available = 0
		elif not self.hardware_breakpoints.has_key(1):
			available = 1
		elif not self.hardware_breakpoints.has_key(2):
			available = 2
		elif not self.hardware_breakpoints.has_key(3):
			available = 3
		else:
			return False

		# Set the debug register in every thread
		for thread_id in self.enumerate_threads():
			context = self.get_thread_context(thread_id=thread_id)

			# Enable the appropiate flag in DR7 to set the breakpoint
			context.Dr7 |= 1 << (available * 2)

			# Save the address of the breakpoint in the free register we found
			if available == 0:
				context.Dr0 = address
			elif available == 1:
				context.Dr1 = address
			elif available == 2:
				context.Dr2 = address
			elif available == 3:
				context.Dr3 = address

			# Set the breakpoint condition
			context.Dr7 |= condition << ((available * 4) + 16)
			# Set the length
			context.Dr7 |= length << ((available * 4) + 18)

			# Set thread context with the breakpoint set
			h_thread = self.open_thread(thread_id)
			kernel32.SetThreadContext(h_thread, byref(context))

		# Update the internal hardware breakpoint array
		self.hardware_breakpoints[available] = (address, length, condition)

		return True

	def bp_set_mem(self, address, size):

		mbi = MEMORY_BASIC_INFORMATION()

		# Check if our call return a full-sized MEMORY_BASIC_INFORMATION struct
		if kernel32.VirtualQueryEx(self.h_process, address, byref(mbi), sizeof(mbi)) < sizeof(mbi):
			return False

		current_page = mbi.BaseAddress

		# Set permissions in all apges that are affected by our mem breakpoint
		while current_page < address + size:

			self.guarded_pages.append(current_page)

			old_protection = c_ulong(0)
			if not kernel32.VirtualProtectEx(	self.h_process, 
												current_page, size, 
												mbi.Protect | PAGE_GUARD, 
												byref(old_protection)):
				return False

			current_page += self.page_size

		self.memory_breakpoints[address] = (address, size, mbi)
		return True


	def display_context(self):

		print "[*] Registers for thread ID: 0x%08x at breakpoint." % self.h_thread
		print "[**] EIP: 0x%08x, ESP: 0x%08x, EBP: 0x%08x" % (self.context.Eip, self.context.Esp, self.context.Ebp)
		print "[**] EAX: 0x%08x, EBX: 0x%08x, ECX: 0x%08x, EDX: 0x%08x" % (	self.context.Eax, self.context.Ebx, 
																			self.context.Ecx, self.context.Edx)

	def ask(self, bk_type, slot=None, size=None):

		answer = raw_input("[*] Do you want to remove the breakpoint? [y/n] {n default} - ")
		if answer == "y":
			if bk_type == "s":
				self.bp_del_soft()
			elif bk_type == "h":
				self.bp_del_hw(slot)
			elif bk_type == "m":
				print "[*] Memory breakpoints are removed by default."
				self.bp_del_mem() # Only need to remove from internal list
			else:
				print "[-] Incorrect type of breakpoint. Doing nothing."
		else:
			if bk_type == "m":
				self.bp_set_mem(self.exception_address, size)
			# Make eip advance (+1 for \xcc +1 to next inst) DOES NOT WORK!
			#self.context.Eip += 2
			#kernel32.SetThreadContext(self.h_thread,byref(self.context))

	def bp_del_soft(self):
		# Remove breakpoint from breakpoint list
		if self.breakpoints.has_key(self.exception_address):
			# this is where we handle the breakpoints we set 
			# first put the original byte back
			self.write_process_memory(self.exception_address, self.breakpoints[self.exception_address])
			del self.breakpoints[self.exception_address]
			print "[*] Soft breakpoint removed."
		else:
			print "[*] Breakpoint address is not registered so it is not removed. Doing nothing."

	def bp_del_hw(self, slot):
		
		# Disable the breakpoint for all active threads
		for thread_id in self.enumerate_threads():

			context = self.get_thread_context(thread_id=thread_id)
			
			# Reset the flags to remove the breakpoint
			context.Dr7 &= ~(1 << (slot * 2))

			# Zero out the address
			if   slot == 0: 
				context.Dr0 = 0x00000000
			elif slot == 1: 
				context.Dr1 = 0x00000000
			elif slot == 2: 
				context.Dr2 = 0x00000000
			elif slot == 3: 
				context.Dr3 = 0x00000000

			# Remove the condition flag
			context.Dr7 &= ~(3 << ((slot * 4) + 16))

			# Remove the length flag
			context.Dr7 &= ~(3 << ((slot * 4) + 18))

			# Reset the thread's context with the breakpoint removed
			h_thread = self.open_thread(thread_id)
			kernel32.SetThreadContext(h_thread, byref(context))
			
		# remove the breakpoint from the internal list.
		if self.hardware_breakpoints.has_key(slot):
			del self.hardware_breakpoints[slot]

		print "[*] Hardware breakpoint removed."

		return True

	def bp_del_mem(self):
		if self.exception_address in self.guarded_pages:
			self.guarded_pages.remove(self.exception_address)
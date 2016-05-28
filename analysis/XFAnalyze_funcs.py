import os
import json
from win32api import GetFileVersionInfo, LOWORD, HIWORD

from idc import *
from idaapi import *

'''
XFAnalyze_funcs.py, Sebastian Apelt, siberas, 2016

finds:
- jfCacheManager::getCacheManager
- jfCacheManager::allocMemory
- jfCacheManager_alloc # ab v10 wrapper um allocMemory!
- jfCacheManager::freeMemory
- jfCacheManager_free
- jfCacheManager_active # value in .data which tells if jfCacheMgr should be used or not
- cacheMgr_ptr # ptr to cacheMgr structure stored in .data
- <xfaobj>.isPropertySpecified scripting method entry point
'''

# unset this if you don't want the func names to be set in your idb!
setnames = True

# unset this if you don't want your module base to be rebased to 0
rebase = False

# unset this if you don't run this code snippet in an automated 
# way which needs ida to be closed after finishing its work
exitOnFinish = False

# if you want to log output to a file set dolog to True...
dolog = False
logfile = os.path.abspath(".\\log.txt")
if len(ARGV) > 1:
	import datetime
	logfile = ARGV[1] + "\\log_%s.txt" % datetime.datetime.now().isoformat().replace(":", "_")
	
# user later for symbol export. set a non-existant func flag to "mark" it
# ok ok, let's call it a hack... ^^
SELF_FLAG = pow(2, 12)

xfadb = AskFile(0, "*.json", "Select the XFAdb_v941.json file")
fh = open(xfadb)
objdict_v941 = json.loads(fh.read())
fh.close()

textstart	= get_segm_by_name(".text").startEA
textend 	= get_segm_by_name(".text").endEA

meth_type_off = 8
meth_getScriptTable_off = 0x34

syms = {}

###> some helper funcs

def isValidCode(addr):
	if textstart <= addr < textend:
		return True
	return False

def seek_vtable_end(addr):
	while(Dword(addr) and isValidCode(Dword(addr))):
		addr += 4
		if len(list(XrefsTo(addr))) != 0:
			break
	return addr
	
def getvtptr(addr):
	return list(XrefsTo(addr, 0))[0].frm - meth_type_off # get first xref == offset vtable in this case
	
def createsym(address, name):
	demangled_sym = Demangle(name, INF_LONG_DN)
	if demangled_sym != None:
		log("[+] found %s (%s) @ 0x%x" % (name, demangled_sym, address))
		syms["0x%x" % address] = { "name": name, "demangled_name": demangled_sym }
	else:
		log("[+] found %s @ 0x%x" % (name, address))
		syms["0x%x" % address] = { "name": name, "demangled_name": name }
		
	if setnames:
		MakeName(address, name)
		SetFunctionFlags(address, SELF_FLAG)
		
def log(s):
	if dolog:
		fh = open(logfile, "a")
		fh.write(s + "\n")
		fh.close()
	print s
			
		
###> let's go !
	
log("\n[+] starting analysis of acroform.api")
if dolog == True:
	log("[+] writing logs to '%s'" % logfile)

if get_imagebase() != 0 and rebase == True:
	log("[+] rebasing module from 0x%x to 0x0" % get_imagebase())
	rebase_program(-get_imagebase(), MSF_FIXONCE)
	log("[+] waiting for analysis to finish...")
	autoWait()
		
targetfile = os.path.abspath(GetInputFile())
log("[+] analyzing file %s" % targetfile)

info = GetFileVersionInfo(targetfile, "\\")
ms = info['FileVersionMS']
ls = info['FileVersionLS']

version = "%02d.%02d.%05d.%05d" % (HIWORD(ms), LOWORD(ms), HIWORD(ls), LOWORD(ls))
majorver = "%d" % HIWORD(ms)
checkver = int("%02d%02d%05d" % (HIWORD(ms), LOWORD(ms), HIWORD(ls)))

if majorver != "10" and majorver != "11":
	majorver = "DC"
	
log("[+] analyzing Adobe Reader %s (version %s) binary..." % (majorver, version))

# the update 05/2016 from AR DC v15.10.20060 to AR DC 15.16.20039 and 20041 (AcroForm v15.16.20039.54196)
# and update from AR 11.0.15 to 11.0.16 removed the jfCacheManager_active check. 
# => all allocations are now handled by the OS Heap via malloc!
if majorver == "DC" and checkver > 151020060:
	log("[!] found newer version than DC v15.10.20060 => jfCacheManager is disabled in this version!!")
	sys.exit(1)
if majorver == "11" and checkver > 110000015:
	log("[!] found newer version than 11.0.15 => jfCacheManager is disabled in this version!!")
	sys.exit(1)

log("[+] waiting for initial analysis to finish...")
autoWait()

log("[+] now search offsets...")
	
'''	
identify jfCacheManager::allocMemory and jfCacheManager::allocMemoryMin
heuristic: 
- we search for a subfunction of jfCacheManager::allocMemory/Min called jfCacheManager::getMemoryCache!
  + jfCacheManager::getMemoryCache contains a unique binary pattern for AR10/11:
    mov edi, 100h				# BF 00 01 00 00
    cmp esi, edi				# 3B  F7
  + ...and a unique pattern for AR DC:
    cmp [ebp+var_4], 100h		# 81 7D FC 00 01 00 00
- jfCacheManager::getMemoryCache is called ONLY by jfCacheManager::allocMemory/Min
- identify allocMemory from allocMemoryMin by checking the return operand. 
  + allocMemoryMin is called with 2 parameters => allocMemoryMin ends with retn 8
  + allocMemory    is called with 1 parameter  => allocMemor     ends with retn 4
'''
pattern_addr = FindBinary(0, SEARCH_DOWN, "BF 00 01 00 00 3B  F7") # works for AR10/11
if pattern_addr == BADADDR:
	pattern_addr = FindBinary(0, SEARCH_DOWN, "81 7D FC 00 01 00 00") # for AR DC we need cmp [ebp+var_4], 100h == 81 7D FC 00 01 00 00
	if pattern_addr == BADADDR:
		raise Exception("could not find offset for jfCacheManager::getMemoryCache!")

jfCacheManager_getMemoryCache = get_func(pattern_addr).startEA
# jfCacheManager::getMemoryCache(jfCacheManager *this_jfCacheManager, unsigned int *ptr_size, unsigned int size_times_2)
createsym(jfCacheManager_getMemoryCache, "_ZN14jfCacheManager14getMemoryCacheERjj")
		
xrefs = []
for xref in XrefsTo(jfCacheManager_getMemoryCache, 0):
	xrefs.append(xref)
	
if len(xrefs) != 2:
	raise Exception("got != 2 xrefs to jfCacheManager::getMemoryCache o_O")
		
# 83 3D X4 X3 X2 X1 00 # X1X2X3X4 is rva to jfCacheManager_active value in .data section
parent1 = get_func(xrefs[0].frm)
jfCacheManager_active_pattern1 = FindBinary(parent1.startEA, SEARCH_DOWN, "83 3D")
if jfCacheManager_active_pattern1 == BADADDR or Byte(jfCacheManager_active_pattern1 + 6) != 0:
	raise Exception("could not find jfCacheManager_active pattern :(")
jfCacheManager_active1 = Dword(jfCacheManager_active_pattern1 + 2)
	
parent2 = get_func(xrefs[1].frm) 
jfCacheManager_active_pattern2 = FindBinary(parent2.startEA, SEARCH_DOWN, "83 3D")
if jfCacheManager_active_pattern2 == BADADDR or Byte(jfCacheManager_active_pattern1 + 6) != 0:
	raise Exception("could not find jfCacheManager_active pattern :(")
jfCacheManager_active2 = Dword(jfCacheManager_active_pattern2 + 2)
	
if jfCacheManager_active1 != jfCacheManager_active2:
	raise Exception("could not identify address of jfCacheManager_active :(")
			
jfCacheManager_active = jfCacheManager_active1
createsym(jfCacheManager_active, "jfCacheManager_active")
		
jfCacheManager_allocMemory = 0
jfCacheManager_allocMemoryMin = 0
checkaddr1 = parent1.endEA - 3
checkaddr2 = parent2.endEA - 3
	
if GetMnem(checkaddr1) == "retn" and GetMnem(checkaddr2) == "retn":
	if GetOpnd(checkaddr1, 0) == "4":
		jfCacheManager_allocMemory = parent1.startEA
		if GetOpnd(checkaddr2, 0) == "8":
			jfCacheManager_allocMemoryMin = parent2.startEA
		else:
			raise Exception("could not identify jfCacheManager_allocMemory/Min (retn 4 in func1, but not retn 8 in func2)")
	elif GetOpnd(checkaddr1, 0) == "8":
		jfCacheManager_allocMemoryMin = parent1.startEA
		if GetOpnd(checkaddr2, 0) == "4":
			jfCacheManager_allocMemory = parent2.startEA
		else:
			raise Exception("could not identify jfCacheManager::allocMemory/Min (retn 8 in func1, but not retn 4 in func2)")
	
if jfCacheManager_allocMemory is 0 or jfCacheManager_allocMemoryMin is 0:
	raise Exception("could not identify jfCacheManager::allocMemory/jfCacheManager::allocMemoryMin")
	
# jfCacheManager::allocMemory(jfCacheManager *this, size_t size)
createsym(jfCacheManager_allocMemory, "_ZN14jfCacheManager11allocMemoryEj")
# jfCacheManager::allocMemoryMin(jfCacheManager *this, unsigned int *, unsigned int)
createsym(jfCacheManager_allocMemoryMin, "_ZN14jfCacheManager14allocMemoryMinERjj")
		
# find jfCacheManager_alloc
jfCacheManager_alloc = 0
	
# in v10 and v11 we can spot a wrapper function which is called from over 800 xrefs!
if majorver == "10" or majorver == "11":
	for xref in XrefsTo(jfCacheManager_allocMemory, 0):
		startaddr = get_func(xref.frm).startEA
		if len(list(XrefsTo(startaddr, 0))) > 800:
			jfCacheManager_alloc = startaddr
			break
# in DC we use the func Concurrency::details::...::_NewTokenState() -> the second call is the call we search!
else: 
	# find func
	found = False
	for addr, name in Names():
		if name.find("NewTokenState") != -1:
			found = True
			break
				
	if not found:
		raise Exception("could not find 'NewTokenState' function")
		
	callnr = 2
	func = get_func(addr)
	for head in Heads(start = func.startEA, end=func.endEA):
		inst = GetDisasm(head)		
		if inst.startswith("call"):
			callnr -= 1
			if callnr == 0:
				jfCacheManager_alloc = GetOperandValue(head, 0)
				break		
	
if jfCacheManager_alloc == 0:
	raise Exception("jfCacheManager_alloc could not be found!")
		
createsym(jfCacheManager_alloc, "jfCacheManager_alloc")

'''
identify jfCacheManager::freeMemory and jfCacheManager::getCacheManager
heuristic: 
- jfCacheManager_active is only referenced by 4 functions (only true for AR v10/11: for Solaris version 9.4.1 we also have a reference to jfCacheManager::setCaching)
  + jfCacheManager::allocMemory		<- we already have that one
  + jfCacheManager::allocMemoryMin	<- we already have that one
  + jfCacheManager::getCacheManager
  + jfCacheManager::freeMemory
- jfCacheManager::getCacheManager: identify it by the heuristic that cmp [jfCacheManager_active], X is always followed by a jnz. luckily this seems stable for versions 10/11/DC!
- jfCacheManager::freeMemory: the remaining one.. ;P
'''
jfCacheManager_freeMemory = 0
jfCacheManager_getCacheManager = 0
xrefs = []
for xref in XrefsTo(jfCacheManager_active, 0):
	funcstart = get_func(xref.frm).startEA
	# skip the ones we already have
	if funcstart == jfCacheManager_allocMemory or funcstart == jfCacheManager_allocMemoryMin:
		continue
	xrefs.append(xref.frm)
		
if len(xrefs) != 2:
	raise Exception("seems like we have more than 4 xrefs to jfCacheManager_active. can't find freeMemory :(")
		
# is xrefs[0] our candidate jfCacheManager::getCacheManager? 
for i in range(xrefs[0], xrefs[0] + 10):
	if Byte(i) == 0x75: # look for the JNZ (0x75) => jfCacheManager::getCacheManager
		jfCacheManager_getCacheManager = get_func(xrefs[0]).startEA
		xrefs.remove(xrefs[0])				
		jfCacheManager_freeMemory = get_func(xrefs[0]).startEA # remaining one in array is freeMemory!
		break	
			
# no hit? then it must be the other way round :P
if jfCacheManager_getCacheManager == 0:
	jfCacheManager_getCacheManager = get_func(xrefs[1]).startEA
	jfCacheManager_freeMemory = get_func(xrefs[0]).startEA
		
# jfCacheManager::freeMemory(jfCacheManager *this, void *)
createsym(jfCacheManager_freeMemory, "_ZN14jfCacheManager10freeMemoryEPv") 
# jfCacheManager::getCacheManager(jfCacheManager *this, unsigned int)
createsym(jfCacheManager_getCacheManager, "_ZN14jfCacheManager15getCacheManagerEj") 
	
'''	
in order to find and walk the cacheManager we need to be able to find it first
heuristic to spot the cacheMgr offset:
- jfCacheManager::getCacheManager calls jfThreadLocalStorage::getThreadStorage
	.text:0000E44B                 push    0Bh  
 	.text:0000E44D                 call    jfThreadLocalStorage__getThreadStorage
-> identify the push 0Bh, then follow the call to getThreadStorage (stable for 10/11/DC, for v9 it is push 0Ch!)
- in this function scan down until 2nd call instruction (v10 and 11) and until the 3rd call inst for DC
- finding the pointer in this func is a bit dirty:

v10:
push    0
mov     eax, offset sub_20D7AA15
call    __EH_prolog3
test    byte ptr dword_2124BF88, 1
mov     esi, offset unk_2124BF84		<- THIS
 
v11:
push    0
mov     eax, offset sub_5BFAAE
call    __EH_prolog3
test    byte ptr dword_AB8468, 1
mov     esi, offset unk_AB8464		<- THIS
 
DC:
loc_764F7:	<- end of function!
mov     eax, offset unk_AFB58C		<- THIS
mov     ecx, [ebp+var_C]
mov     large fs:0, ecx
pop     ecx
mov     esp, ebp
pop     ebp
retn
'''
pattern_addr = FindBinary(jfCacheManager_getCacheManager, SEARCH_DOWN, "6a 0b")
if pattern_addr == BADADDR:
	raise Exception("could not spot binary pattern to find the call to jfThreadLocalStorage::getThreadStorage")

jfThreadLocalStorage_getThreadStorage = GetOperandValue(2 + pattern_addr, 0) # 2 == len(push 0x0b)
# jfThreadLocalStorage::getThreadStorage(jfThreadLocalStorage::eCacheType, unsigned int)
createsym(jfThreadLocalStorage_getThreadStorage, "_ZN20jfThreadLocalStorage16getThreadStorageENS_10eCacheTypeEj")
	
getCacheMgr_func = 0
callnr = 3 if majorver == "DC" else 2
func = get_func(jfThreadLocalStorage_getThreadStorage)
for head in Heads(start = func.startEA, end=func.endEA):
	inst = GetDisasm(head)
	#print "[+] 0x%x %s" % (head, inst)
	if inst.startswith("call"):
		callnr -= 1
		if callnr == 0:
			# we found the call to the function which references data.cacheMgr
			getCacheMgr_func = GetOperandValue(head, 0)
			break
		
if getCacheMgr_func == 0:
	raise Exception("could not find getCacheMgr_func!")
		
cacheManager_ptr = 0
func = get_func(getCacheMgr_func)
# now on DC search for last mov eax, <addr> in function
if majorver == "DC":
	for head in Heads(start = func.startEA, end=func.endEA):
		inst = GetDisasm(head)
		#print "[+] 0x%x %s" % (head, inst)
		if inst.startswith("mov"):
			if GetOpnd(head, 0) == "eax":					
				datarefs = list(DataRefsFrom(head))
				if len(datarefs) != 1:
					continue # we need exactly 1 .data reference
				cacheManager_ptr = datarefs[0]
				# do not break loop, search for the last occurence!
					
# else search for first mov esi, <addr> in function
else:
	for head in Heads(start = func.startEA, end=func.endEA):
		inst = GetDisasm(head)
		#print "[+] 0x%x %s" % (head, inst)
		if inst.startswith("mov"):
			if GetOpnd(head, 0) == "esi":								
				datarefs = list(DataRefsFrom(head))
				if len(datarefs) != 1:
					continue # we need exactly 1 .data reference
				cacheManager_ptr = datarefs[0]
					
if cacheManager_ptr == 0:
	raise Exception("cacheManager_ptr could not be found!")
					
createsym(cacheManager_ptr, "cacheManager_ptr")		
	
'''
the last symbol we search for is xfa.isPropertySpecified

methodology:
- find SourceSetModel Type Method
- the only Xref will point to the object's vtable in .data
- now we can find the beginning of the vtable and at offset 0x34 we find the getScriptTable func
- from there on we walk the moScriptTable structures until we find "isPropertySpecified" and its function pointer
'''
typeid = 0x7e00 # XFASourceSetModelImpl, model < node
pattern_addr = FindBinary(0, SEARCH_DOWN, "b8 %x %x 00 00 c3" % (typeid & 0xff, typeid >> 8)) # mov eax, XXYYh; retn		
log("[+] found 'mov eax, %x; retn' binary pattern @ 0x%x" % (typeid, pattern_addr))
	
vtable_address = getvtptr(pattern_addr)		
log("[+] vt start @ 0x%x" % vtable_address)
		
getScriptTable_ptr = vtable_address + meth_getScriptTable_off
getScriptTable = Dword(getScriptTable_ptr)
log("[+] getScriptTable ptr @ 0x%x" % getScriptTable_ptr)
log("[+] getScriptTable @ 0x%x" % getScriptTable)
		
fnc = get_func(getScriptTable)	
head = list(Heads(start=fnc.startEA, end=fnc.endEA))[0]
dataloc = GetOperandValue(head, 1)		
nodeclass = Dword(dataloc)
classname = GetString(Dword(nodeclass+0x04), -1, ASCSTR_C)
addr = Dword(nodeclass+0x0c)	
funcaddr = 0
found = False
while(Dword(addr) != BADADDR and Dword(addr)):		
	methodname = GetString(Dword(Dword(Dword(Dword(addr)))), -1, ASCSTR_C)
	funcaddr = Dword(Dword(addr)+4)
	if methodname == "isPropertySpecified":
		found = True
		break
	addr += 4
	
if found == False:
	raise Exception("could not find method 'isPropertySpecified' :(")
	
createsym(funcaddr, "xfa_isPropertySpecified")	
	
log("[+] analysis done!")	
log("[+] results:\n%s" % json.dumps(syms, indent = 2))

if exitOnFinish == True:	
	Exit(0)

'''
AR 9.4.1 lists 334 *::Type methods for 334 distinct objects
this script extracts
- object name 
- corresponding type id
- vtable address
- vtable entries
'''

from idaapi import *
from idc import *
from idautils import *

import json

'''
objdict[<id>] = 	{ 	"name": "", 					
						"vtaddr": "0xXXX", 
						"vtable_funcs": [ {	"name" : "", "undecorated" : "", "rva" : ""	}, ...]
 					}
'''
objdict = {}

meth_type_off = 0x8
meth_getScriptTable_off = 0x34

textstart	= get_segm_by_name(".text").startEA
textend 	= get_segm_by_name(".text").endEA

# we need a blacklist because a few objects do NOT have a unique type id for some reason
# these have to be sorted out to avoid false assignments
blacklist = []

def isValidCode(addr):
	if textstart <= addr < textend:
		return True
	return False

def seek_vtable_end(addr):
	while(Dword(addr) and len(list(XrefsTo(addr))) == 0 and isValidCode(Dword(addr))):
		addr += 4
	return addr
	
def getvtptr(addr):
	return list(XrefsTo(addr, 0))[0].frm - meth_type_off # get first xref == offset vtable in this case
		
		
def parseProperties(addr):
	print "[+] parsing props @ 0x%x" % addr
	props = [] # { "name" : "", "getter" : "", "setter" : "" }
	while(Dword(addr) != BADADDR and Dword(addr)):		
		propname = GetString(Dword(Dword(Dword(Dword(addr)))), -1, ASCSTR_C)
		if propname == None:
			propname = "value_direct_" # for assignment obj = "hi" instead of obj.value = "hi"
			
		getter = Dword(Dword(addr)+4)
		setter = Dword(Dword(addr)+8)
		props.append( { "name" : propname, "getter" : "0x%x" % getter, "setter" : "0x%x" % setter } )		
		print "prop %s, get 0x%x, set 0x%x" % (propname, getter, setter)		
		addr += 4
	return props
	
def parseMethods(addr):
	print "[+] parsing meths @ 0x%x" % addr
	meths = [] # { "name" : "", "rva" : "" }
	while(Dword(addr) != BADADDR and Dword(addr)):		
		methodname = GetString(Dword(Dword(Dword(Dword(addr)))), -1, ASCSTR_C)
		funcaddr = Dword(Dword(addr)+4)
		meths.append( { "name" : methodname, "rva" : "0x%x" % funcaddr } )
		addr += 4
	return meths
	
	
try:
	# go through all functions and look for the ::Type methods!
	for funcaddr in Functions():
		funcname = Demangle(GetFunctionName(funcaddr), INF_LONG_DN)
		if not funcname:
			continue
		if funcname.find("::Type(void)") == -1:
			continue # we only want the ::Type getter functions
				
		# get first instruction and extract the typeid
		typefnc = get_func(funcaddr)
		for head in Heads(start = typefnc.startEA, end = typefnc.endEA):
			break # get first instruction
		inst = GetDisasm(head)
		res = re.match(".*,\s+([0-9A-F]+)", inst)
		if res == None:
			print "[!] could not get typeid (first inst of func %s starting at 0x%x is '%s'..." % (funcname, typefnc.startEA, inst)
			continue
				
		typeid = "0x" + res.group(1)
		
		if typeid in blacklist:
			print "[!] skipping typeid %s (found on blacklist)" % typeid
			continue
		
		#print "0x%x - %s, id: %s" % (funcaddr, funcname, typeid)
		if typeid in objdict:
			'''
			special cases we need to handle:
			- XFADataModelImpl::Type and XFALogMessageImpl::Type both return 0x7200
			- XFADataValueImpl::Type and XFALogMessageDataImpl::Type both return 0x7202
			- XFADataGroupImpl::Type and XFALogMessageHandlerImpl::Type both return 0x7203
			distinguish them by the length of the found vtables! XFALogMessageDataImpl and XFALogMessageHandlerImpl have very short vtables!
			'''
			if typeid == "0x7200" or typeid == "0x7202" or typeid == "0x7203":
				print "[!] special case for typeid %s" % typeid
				existing_entry_vtlen = (seek_vtable_end(int(objdict[typeid]["vtaddr"], 16)) - int(objdict[typeid]["vtaddr"], 16)) / 4
				new_vtlen = (seek_vtable_end(getvtptr(typefnc.startEA)) - getvtptr(typefnc.startEA)) / 4
				# only need action if new vtable seems to be the longer one, then this is probably XFADataValue
				if new_vtlen > existing_entry_vtlen:
					objdict.pop(typeid)
				else:
					continue # if we do not replace the old entry we've already found the correct one.
			else:
				'''
				for any other case drop the typeid entry from the dict and add it to the blacklist
				'''
				print "[!] id %s (%s) already present seen for object %s -> blacklisting it" % (typeid, funcname, objdict[typeid]["name"])
				blacklist.append(typeid)
				objdict.pop(typeid)		

		# "vtable_funcs": [ { "name" : "", "undecorated" : "", "rva" : ""	}, ...]
		vtptr = getvtptr(typefnc.startEA)
		
		# now parse vtable and save function names
		vtable_funcs = []
		vtlen = (seek_vtable_end(vtptr) - vtptr) / 4
		for addr in range(vtptr, vtptr + vtlen*4, 4):
			funcaddr = Dword(addr)
			vtable_funcs.append( { 	"name" : GetFunctionName(funcaddr), 
									"undecorated": Demangle(GetFunctionName(funcaddr), INF_LONG_DN), 
									"rva" : "0x%x" % funcaddr } )
				
		hierarchy = []
		scriptmethods = {} 	
		attributes = {}				
		
		getScriptTable_index = meth_getScriptTable_off / 4
		
		# now parse the moscripttable for getter/setter funcs and script methods		
		if len(vtable_funcs) >= getScriptTable_index:
			if vtable_funcs[getScriptTable_index]["undecorated"].find("getScriptTable") != -1:
				getScriptTable = int(vtable_funcs[getScriptTable_index]["rva"], 16)
				fnc = get_func(getScriptTable)
								
				cnt = 0
				for head in Heads(start=fnc.startEA, end=fnc.endEA):
					inst = GetDisasm(head)
					#print "[+] 0x%x %s" % (head, inst)						
					# following regex is for solaris. the reference will look like this:
					# mov eax, ds:(_ZN14XFAPictureImpl13moScriptTableE_ptr - 118AAA4h)[ecx]
					res = re.match(".*\((\w+)\ -\ \w+\).*", inst)
													
					if res != None:
						sym = res.group(1)
						break
										
				dataloc = Dword(LocByName(sym))
					
				objname = ""
				while(1): # we break if we hit 0 => end of the object hierarchy!
					classname = GetString(Dword(dataloc+0x04), -1, ASCSTR_C)
					hierarchy.append(classname)
						
					if objname == "":
						objname = classname	
						'''
						TODO: 
						check this! think it's not possible to check this way. we get too many false alarms due to inheritance problems
							
						# make sure we're on the right track by checking against our target object name
						if objname.lower() not in name_targetobj.lower():
							print "%s - %s" % (objname.lower(), name_targetobj.lower())
							oops
						'''										
						print "[+] parsing structure for class '%s' @ 0x%x" % (objname, dataloc)
					else:
						print "[+] parsing structure for subclass '%s' @ 0x%x" % (classname, dataloc)
							
					# { "tree" : [ { "name": "", "rva": "" }, ... ], "node": [...]...}
					attributes[classname] = []
					propsptr = Dword(dataloc+0x08)
					if propsptr != 0:
						attributes[classname] = parseProperties(propsptr)
							
					scriptmethods[classname] = []
					methptr = Dword(dataloc+0x0c)
					if methptr != 0:
						scriptmethods[classname] = parseMethods(methptr)							
						
					# deref the first dword to continue
					dataloc = Dword(dataloc)
					if dataloc == 0:
						break
										
		
		objdict[typeid] = { 
							"name" : funcname.split("::")[0], 							
							"vtaddr": "0x%x" % vtptr, 
							"vtlen": (seek_vtable_end(getvtptr(typefnc.startEA)) - getvtptr(typefnc.startEA)) / 4, 
							"vtable_funcs" : vtable_funcs, 
							"hierarchy" : hierarchy,
							"scriptmethods" : scriptmethods,
							"attributes" : attributes
						} 
				
	out = json.dumps(objdict, indent=2)
	outfile = AskFile(1, "XFAdb_v941.json", "Select where to save the XFAdb_v941.json file")
	fh = open(outfile, "w")
	fh.write(out)
	fh.close()
	print "[+] done."
	
except Exception, e:
	print "[!] Exception: %s" % e
	

	

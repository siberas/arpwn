import os
import json
from win32api import GetFileVersionInfo, LOWORD, HIWORD

from idc import *
from idaapi import *

'''
XFAnalyze_moScriptTable.py, Sebastian Apelt, siberas, 2016

finds:
- all entrypoints for getter/setter methods of object-properties
- all entrypoints for scripting methods
- vtable functions (as good as possible) <- still rather crude implementation...
'''

# unset this if you don't want the func names to be overwritten!
setnames = True

# if you want to log output to a file set dolog to True...
dolog = False
logfile = os.path.abspath(".\\log.txt")
if len(ARGV) > 1:
	import datetime
	logfile = ARGV[1] + "\\log_%s.txt" % datetime.datetime.now().isoformat().replace(":", "_")
	
xfadb = AskFile(0, "*.json", "Select the XFAdb_v941.json file")
fh = open(xfadb)
objdict_v941 = json.loads(fh.read())
fh.close()

meth_type_off = 0x8
meth_getScriptTable_off = 0x34

textstart	= get_segm_by_name(".text").startEA
textend 	= get_segm_by_name(".text").endEA
datastart	= get_segm_by_name(".data").startEA
dataend 	= get_segm_by_name(".data").endEA
	
SELF_FLAG = pow(2, 12)
	
def isValidCode(addr):
	if textstart <= addr < textend:
		return True
	return False
	
	
def isValidData(addr):
	if datastart <= addr < dataend:
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

	
def log(s):
	if dolog:
		fh = open(logfile, "a")
		fh.write(s + "\n")
		fh.close()
	print s
	
	
symcount = 0 # count how many symbols we set
def createsym(address, name, symlog=True):
	global symcount
	symcount += 1	
	s = "[+] MakeName: 0x%x -> %s" % (address, name)	
	try:
		dem = Demangle(name, INF_LONG_DN)
		if dem != None:
			s += " (%s)" % dem
	except:
		pass
		
	if symlog == True:
		log(s)
	
	if setnames:
		name = name.replace("#", "HASHSYM_")
		set_name(address, name, SN_NOWARN)
		SetFunctionFlags(address, SELF_FLAG)
		
		
targetfile = os.path.abspath(GetInputFile())
log("[+] analyzing file %s" % targetfile)

log("[+] waiting for initial analysis to finish...")
autoWait()

info = GetFileVersionInfo(targetfile, "\\")
ms = info['FileVersionMS']
ls = info['FileVersionLS']
ver = "%02d.%02d.%05d.%05d" % (HIWORD(ms), LOWORD(ms), HIWORD(ls), LOWORD(ls))
majorver = "%d" % HIWORD(ms)

if majorver != "10" and majorver != "11":
	majorver = "DC"
	
log("[+] target version: Adobe Reader %s (version %s)" % (majorver, ver))

objdict = {}	
# now parse the moScriptTable structures
for typeid in objdict_v941:
	'''
	objdict_v941 is a dictionary with typeid strings as keys and object dicts as values
	
	each object dictionary has following structure:
	{
		"name": 		<STR: NAME OF OBJECT>, 
		"vtaddr": 		<STR: VTABLE ADDRESS>, 
		"vtlen": 		<STR: LENGTH OF VTABLE>, 
		"vtable_funcs": <ARRAY: VTABLE FUNCTION DICTS (see below)>,
		"hierarchy": 	<ARRAY: CLASS HIERARCHY, eg. ["boolean", "content", "node", "tree", "object"]>, 
		"properties": 	<DICT (see below)>, 
		"scriptmethods":<DICT (see below)>
	}
	
	"vtable_funcs": 	
	the vtable function dicts have rva, name and the undecorated name as entries, eg.:
	{
        "rva": 			"0x7a23e6", 
        "name": 		"_ZN11XFANodeImpl6removeEi", 
        "undecorated": 	"XFANodeImpl::remove(int)"
    }
	
	"properties":
	dictionary where keys are the various hierarchy levels. 
	values are arrays of dictionaries containing "getter", "setter" and "name" entries
	example:
	{
      "node": [ { "getter": "0x79b1a0", "name": "isContainer", "setter": "0x0" }, 
				{ "getter": "0x79aa16", "name": "isNull", "setter": "0x0" }, 
				...
			  ],
	  "tree": [ { "getter": "0x7dde8a", "name": "nodes", "setter": "0x0" }, 
				{ "getter": "0x7dc08a", "name": "name", "setter": "0x7dbffe" }, 
				...
			  ],
	  ...
	}
	
	"scriptmethods":
	dictionary where keys are the various hierarchy levels. 
	values are arrays of dictionaries containing "rva" and "name" entries
	example:
	{
      "node": [ { "rva": "0x79cff2", "name": "clone" }, 
				{ "rva": "0x79d3ba", "name": "isPropertySpecified" }, 
				...
			  ],
	  "manifest": [ { "rva": "0x78c394", "name": "evaluate" }, 
					{ "rva": "0x78bd4a", "name": "execValidate" }, 
				    ...
			      ],
	  ...
	}
	
	'''
	obj = objdict_v941[typeid]
	typeid = int(typeid, 16)
	log("\n\n[+] obj %s, typeid 0x%x" % (obj["name"], typeid))
	log("[+] original obj from AR for Solaris v941: len(properties): %d, len(methods): %d, len(vtable): %d" % (len(obj["properties"]), len(obj["scriptmethods"]), obj["vtlen"]))
			
	# reset call hierarchy, scripting method, properties and the vtable addresses for the new object
	obj["hierarchy"] = []
	obj["scriptmethods"] = {}
	obj["properties"] = {}
	obj["vtaddr"] = "0"		

	log("[+] finding moScriptTable data ptr...")
	pattern_addr = FindBinary(0, SEARCH_DOWN, "b8 %x %x 00 00 c3" % (typeid & 0xff, typeid >> 8)) # mov eax, XXYYh; retn
	if pattern_addr == BADADDR:
		log("[-] could not find binary pattern for 'mov eax, %x; retn' => skip it!" % typeid)
		continue
	
	log("[+] found 'mov eax, %x; retn' binary pattern @ 0x%x" % (typeid, pattern_addr))
	
	vtable_address = getvtptr(pattern_addr)
	obj["vtaddr"] = "0x%x" % vtable_address	
	log("[+] vtable start @ 0x%x" % vtable_address)
	createsym(vtable_address, obj["name"] + "_vtable", symlog=False)
		
	# check size of vtable 
	vtable_end_address = seek_vtable_end(vtable_address)
	vtentries = ( vtable_end_address - vtable_address ) / 4
	
	# yes, this is a weak heuristic! remove it if you don't like it ;)
	# most methods WILL match, some XFA methods have been removed and added, though. 
	# so this will NOT be accurate if count(added_vt_methods) == count(removed_vt_methods)!
	if obj["vtlen"] == vtentries:
		pass
	else:
		# if the count does NOT match then obviously methods were removed or added. 
		# for xfa objects we can at least match until the XFATreeImpl methods:
		# XFAObjectImpl has 20 methods which stay the same and XFATreeImpl also has 20 unchanged methods
		if vtentries >= 0x50: # => xfa-obj (see below)
			obj["vtable_funcs"] = obj["vtable_funcs"][:40]
		else:
			obj["vtable_funcs"] = []
		
	# update vtable entry count
	obj["vtlen"] = vtentries
	
	# object class contains getScriptTable method. length(object vtable) == 20 => 20*4 = 80 = 0x50 is minimum vtable size 
	if vtentries < 0x50: 
		log("[!] no XFA obj (len(vtable) == %d too small) => no getScriptTable method... skip it!" % (vtentries*4))
		objdict["0x%x" % typeid] = obj
		continue
	
	getScriptTable_ptr = vtable_address + meth_getScriptTable_off
	getScriptTable = Dword(getScriptTable_ptr)
	createsym(getScriptTable, obj["name"] + "_getScriptTable", symlog=False)
	
	log("[+] %s::getScriptTable ptr @ 0x%x" % (obj["name"], getScriptTable_ptr))
	log("[+] %s::getScriptTable @ 0x%x" % (obj["name"], getScriptTable))
	
	# for solaris we have something like the following instr:
	# mov     eax, ds:(_ZN14XFASubformImpl13moScriptTableE_ptr - 118AAA4h)[ecx]
	# extract _ZN14XFASubformImpl13moScriptTableE_ptr via regex
	moScriptTable = None
	fnc = get_func(getScriptTable)
	if fnc is None:
		log("[!] getScriptTable could not be found => skip object!")
		objdict["0x%x" % typeid] = obj
		continue
		
	# simple heuristic check to make sure we're in getScriptTable. 
	# The function is small. maximum of ~0x18 bytes
	if fnc.endEA - fnc.startEA > 0x20:
		log("[!] function too big. this is probably not getScriptTable...! => skip object!")
		objdict["0x%x" % typeid] = obj
		continue
		 		
	cnt = 0
	for head in Heads(start=fnc.startEA, end=fnc.endEA):
		if GetOpnd(head, 0) == "eax" and isValidData(GetOperandValue(head, 1)):
			moScriptTable = GetOperandValue(head, 1)
			
	if not moScriptTable:
		raise Exception("could not find moScriptTable offset")
				
	log("[+] %s::moScriptTable @ 0x%x" % (obj["name"], moScriptTable))
	createsym(moScriptTable, obj["name"] + "_moScriptTable", symlog=False)
		
	while(1): # we break if we hit 0 => end of the class hierarchy!
		classname = GetString(Dword(moScriptTable+0x04), -1, ASCSTR_C)
						
		if len(obj["hierarchy"]) == 0:
			log("[+] parsing %s.moScriptTable @ 0x%x" % (classname, moScriptTable))
		else:
			log("[+] parsing %s.moScriptTable (subclass) @ 0x%x" % (classname, moScriptTable))
			createsym(moScriptTable, classname + "_moScriptTable", symlog=False)

		obj["hierarchy"].append(classname)
			
		####> PARSE PROPERTIES
				
		# { "tree" : [ { "name": "", "rva": "" }, ... ], "node": [...]...}
		obj["properties"][classname] = []
		propsptr = Dword(moScriptTable+0x08)
		if propsptr != 0:
			log("[+] parsing props @ 0x%x" % propsptr)
			createsym(propsptr, "properties_table__%s_%s" % (obj["name"], classname), symlog=False)
			
			while(Dword(propsptr) != BADADDR and Dword(propsptr)):
				propname = GetString(Dword(Dword(Dword(Dword(propsptr)))), -1, ASCSTR_C)
				
				# for assignment obj = "hi" instead of obj.value = "hi"
				if Dword(propsptr) == 0 or Dword(Dword(propsptr)) == 0 or propname == None: 
					propname = "value_direct"
									
				createsym(Dword(propsptr), "property_struct__%s_%s_%s" % (obj["name"], classname, propname), symlog=False)
				createsym(Dword(Dword(propsptr)), "ptr_ptr_string_" + propname, symlog=False)
				createsym(Dword(Dword(Dword(propsptr))), "ptr_string_" + propname, symlog=False)
				
				getter = Dword(Dword(propsptr)+4)				
				setter = Dword(Dword(propsptr)+8)				
					
				obj["properties"][classname].append( { "name" : propname, "getter" : "0x%x" % getter, "setter" : "0x%x" % setter } )		
				#print "prop %s, get 0x%x, set 0x%x" % (propname, getter, setter)		
				propsptr += 4
				
			log("[+] found %d properties" % len(obj["properties"][classname]))
		else:
			log("[!] no properties found")
				
				
		####> PARSE METHODS
		
		obj["scriptmethods"][classname] = []
		methptr = Dword(moScriptTable+0x0c)
		if methptr != 0:
			createsym(methptr, "method_table__%s_%s" % (obj["name"], classname), symlog=False)
			log("[+] parsing methods @ 0x%x" % methptr)
			while(Dword(methptr) != BADADDR and Dword(methptr)):		
				methodname = GetString(Dword(Dword(Dword(Dword(methptr)))), -1, ASCSTR_C)
				createsym(Dword(methptr), "method_struct__%s_%s_%s" % (obj["name"], classname, methodname), symlog=False)
				createsym(Dword(Dword(methptr)), "ptr_ptr_string_" + methodname, symlog=False)
				createsym(Dword(Dword(Dword(methptr))), "ptr_string_" + methodname, symlog=False)
				
				funcaddr = Dword(Dword(methptr)+4)
				if funcaddr != 0:
					obj["scriptmethods"][classname].append( { "name" : methodname, "rva" : "0x%x" % funcaddr } )		
												
				methptr += 4
				
			log("[+] found %d methods" % len(obj["scriptmethods"][classname]))
		else:
			log("[!] no methods found")
					
		# deref the first dword to continue - break if 0 (end of class hierarchy!)
		moScriptTable = Dword(moScriptTable)
		if moScriptTable == 0:
			break
	
	log("[+] finished moScriptTable parsing for object %s!" % obj["name"])
	
	####> NOW SET METHOD AND PROPERTY SYMBOLS
	log("[+] set methods..."	)
	for classname in obj["hierarchy"]:
		c = 0
		for method_dict in obj["scriptmethods"][classname]:
			c += 1
			method_addr = int(method_dict["rva"], 16)
			if method_addr != 0:			
				# check if we've already set a name for this method. if this is the case we omit 
				# the object name as part of the method name since it would be misleading
				method_name = "METHOD_%s_%s_%s" % (obj["name"], classname, method_dict["name"])
				long_method_name = ""
				if Name(method_addr) != "":
					long_method_name = method_name
					method_name = "METHOD_%s_%s" % (classname, method_dict["name"])
									
				log("[%d/%d] set method '%s' => %s" % (c, len(obj["scriptmethods"][classname]), method_name, method_dict["rva"]))
				createsym(method_addr, method_name)
				
				# add long method name to see in the function header which objects call reference this method
				if long_method_name not in GetFunctionCmt(method_addr, 0).split("\n"):
					SetFunctionCmt(funcaddr, GetFunctionCmt(method_addr, 0) + "\n" + long_method_name, 0)
	
	log("[+] set properties...")
	for classname in obj["hierarchy"]:
		c = 0
		for property_dict in obj["properties"][classname]:
			c += 1
			for type in ["getter", "setter"]:
				property_func = int(property_dict[type], 16)
				if property_func != 0:			
					# set getter name just like we did it above
					if Name(property_func) != "":
						property_name = "%s_%s_%s" % (type.upper(), classname, property_dict["name"])
					else:
						property_name = "%s_%s_%s_%s" % (type.upper(),obj["name"], classname, property_dict["name"])
					log("[%d/%d] set property %s '%s' => %s" % (c, len(obj["properties"][classname]), type, property_name, property_dict[type]))
					createsym(property_func, property_name)
				
	objdict["0x%x" % typeid] = obj
	
	
# setting vtable method infos is partly incorrect!!
# remove this if you want to make sure everything is correct...
log("[+] now setting vtable method information...")
for typeid in objdict:
	obj = objdict[typeid]
	typeid = int(typeid, 16)
	log("[+] setting vtable infos for object %s with vtable @ 0x%x" % (obj["name"], int(obj["vtaddr"], 16)))
	
	offset = 0
	for method_dict in obj["vtable_funcs"]:
		method_addr = Dword(int(obj["vtaddr"], 16) + offset)
		log("[%d/%d] %s @ 0x%x" % (offset/4, len(obj["vtable_funcs"]), method_dict["name"], method_addr))
		createsym(method_addr, method_dict["name"])	
		offset += 4	
	
'''
xfadb = AskFile(1, "XFADB_AR_%s_(%s).json" % (majorver, ver), "Select output file for XFADB")
if xfadb != None:
	fh = open(xfadb, "wb")
	fh.write(json.dumps(objdict, indent = 2))
	fh.close()
'''
log("[+] done!")
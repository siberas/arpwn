
from idaapi import *
from idc import *
from idautils import *

import sys
import pefile
from struct import *
from construct import *
import binascii

'''
pdb_dump.py, sebastian apelt, siberas, 2016

script to dump self-defined function symbols to .pdb file
quick&dirty + full of hacks, but works. kindof :P

the functions which are to be dumped have to be marked with SetFunctionFlags(address, SELF_FLAG)
anyone knowns a good way to "mark" certain bytes (not only funcs)? if yes, please tell me so that I can remove this ugly hack :)
'''

# adjust this! the script needs to find the pdb templates
pdbtpl_dir = r"K:\code\python\idapython\scripts\AR"

SELF_FLAG = pow(2, 12)

file = GetInputFilePath()
print "[+] input file: %s" % file
print "[+] loading pe information....."
pe = pefile.PE(file)

section_number = 1
for section in pe.sections:
	if section.Name.find("text") != -1:
		break
	section_number += 1
print "[+] found .text as section number %d" % section_number
	
cnt = 0
# search for self-defined function names (special flag set via SetFunctionFlags)
for address in Functions():
	if GetFunctionFlags(address) & SELF_FLAG != 0:
		cnt += 1

for x in range(2, 6):
	if cnt < pow(10, x):
		break		
pdbtpl = "tpl_%d.pdb" % pow(10,x)
print "[+] reading pdb template %s" % pdbtpl
pdbtpl_data = open("%s\\%s" % (pdbtpl_dir, pdbtpl), "rb").read()	
	
print "[+] setting symbols in pdb..."
imgbase = get_imagebase()
cnt = 0
# search for self-defined function names (special flag set via SetFunctionFlags)
for address in Functions():
	if GetFunctionFlags(address) & SELF_FLAG != 0:
		orgname = get_name(address, address)
		name = Demangle(orgname, INF_SHORT_DN)
		if name == None:
			name = orgname			
		print "[+] setting symbol: %s @ 0x%x" % (name, address)
		off = pdbtpl_data.find("?_XXX_")
		pdbtpl_data = pdbtpl_data[:off] + name + "\x00" + pdbtpl_data[off + len(name) + 1:]
		pdbtpl_data = pdbtpl_data[:(off-6)] + pack("I", (address - (imgbase+0x1000))) + pdbtpl_data[(off-2):]
		pdbtpl_data = pdbtpl_data[:(off-2)] + pack("H", section_number) + pdbtpl_data[off:]
		cnt += 1
				
# delete the unused placeholders
off = 0
while(1):
	off = pdbtpl_data.find("?_XXX_", off)
	if off == -1:
		break
	pdbtpl_data = pdbtpl_data[:off] + "\x00" + pdbtpl_data[(off+1):]
	off += 1	
	
print "[+] successfully set a total of %d self-defined symbols" % cnt
	
dbgstruct = pe.DIRECTORY_ENTRY_DEBUG[0].struct

fh = open(file)
fh.seek(dbgstruct.PointerToRawData)
dbgdata = fh.read(dbgstruct.SizeOfData)
fh.close()

def GUID(name):
	return Struct(name, ULInt32("Data1"), ULInt16("Data2"), ULInt16("Data3"), String("Data4", 8),)

CV_RSDS_HEADER = Struct("CV_RSDS",
	Const(Bytes("Signature", 4), "RSDS"),
	GUID("GUID"),
	ULInt32("Age"),
	CString("Filename"),
)

try:
	dbg = CV_RSDS_HEADER.parse(dbgdata)
except:
	fh = open(file, "rb")
	data = fh.read()
	fh.close()
	off = data.find("RSDS")
	dbgdata = data[off : off+dbgstruct.SizeOfData]
	dbg = CV_RSDS_HEADER.parse(dbgdata)

guid_str = "%08x%04x%04x%s%x" % (dbg.GUID.Data1, dbg.GUID.Data2, dbg.GUID.Data3, dbg.GUID.Data4.encode('hex'), dbg.Age)
guid_str = guid_str.upper()
guid = dbgdata[0x4:0x14] 

fdata = open(file, "rb").read()
timestamp = unpack("I", fdata[pe.DOS_HEADER.e_lfanew + 8: pe.DOS_HEADER.e_lfanew + 0xc])[0]
	
print "[+] raw: %s" % repr(dbgdata)
print "[+] hexlified: %s" % binascii.hexlify(dbgdata)
print "[+] parsed: %s" % dbg
print "[+] GUID: %s (guid raw data: %s)" % (guid_str, binascii.hexlify(guid))
print "[+] AGE: %x" % dbg.Age
print "[+] TIMESTAMP: 0x%x" % timestamp

pdb_data = pdbtpl_data

off = 0
while(1):
	off = pdb_data.find("/LinkInfo", off)
	if off == -1:
		break
	print "[+] /LinkInfo @ 0x%x. fixing timestamp/age/guid fields..." % off
	pdb_data = pdb_data[:(off-0x1c)] + pack("I", timestamp) + pdb_data[(off-0x18):]
	pdb_data = pdb_data[:(off-0x18)] + pack("I", dbg.Age) + pdb_data[(off-0x14):]
	pdb_data = pdb_data[:(off-0x14)] + guid + pdb_data[(off-0x4):]	
	off += 1
	
'''
in order to understand this get yourself a dbgeng.dll with symbols (eg. with Windbg 6.3.9600.17298!)
then have a look at PDB1::OpenValidate4. after the sig cmp loop you have 2 (!) QueryAge calls
dbghelp!PDB1::QueryAge will retrieve the age field from the RSDS structure and compare it afterwards with the one supplied in the pdb
dbghelp!DBI1::QueryAge will retrieve a second (!) age field. this one is not really documented (at least I didn't find any info about it)
you can find the second one by searching the pdb for the static values 0xffffffff followed by 0x01310977. the second age value will be the next dword
'''
print "[+] fixing second age field..."
off = pdb_data.find(binascii.unhexlify("FFFFFFFF77093101"))
if off == -1:
	print "[-] could not find FFFFFFFF77093101 pattern!"
	sys.exit(1)	
pdb_data = pdb_data[:(off+0x08)] + pack("I", dbg.Age) + pdb_data[(off+0x0c):]	
	
outfile = AskFile(1, "%s.pdb" % file.rsplit(".", 1)[0], "chose folder where to save the pdb file")
print "[+] writing pdb to '%s'" % outfile

fh = open(outfile, "wb")
fh.write(pdb_data)
fh.close()

print "[+] place pdb-file in <Symbol folder>\\%s or in executable folder" % guid_str
print "[+] done!"
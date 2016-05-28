# Pwning the Reader with XFA
This git repo contains the material from my Adobe (Acrobat) Reader (10/11/DC) XFA research. The provided material consists of:
- Idapython analysis scripts for symbol recovery
- PDBs for Acroform.api of versions AR 10/11/DC to simplify the debugging process
- Exploit samples to showcase the effectiveness and reliablity of the jfCache flink exploitation method
- Slidedecks from my SyScan360 and Infiltrate 2016 presentations

__The README will be updated during the next days to make the usage of the various scripts easier to understand. Stay tuned!__

## analysis
- __XFAnalyze_Sol941.py__: Idapython script to collect most important symbolic information from Acroform.api (AR for Solaris v9.4.1) -> gives you dictionary 'XFAdb_v941.json' which is needed for script XFAnalyze_funcs.py and XFAnalyze_moScriptTable.py
- __XFAnalyze_funcs.py__: Idapython script collecting jfCacheManager functions and a debugging func via reliable heuristics (tested on AR 10/11/DC) and adding them to your IDB
- __XFAnalyze_moScriptTable.py__: Idapython script to parse moScriptTable structures of all the objects found via XFAnalyze_Sol941.py (most XFA* and jf* objects). Finds entrypoints for scripting methods as well as for property getters and setters and adds them to your IDB
- __pdb_dump.py__: Very crude implementation for dumping the symbols which were found via XFAnalyze_funcs.py and XFAnalyze_moScriptTable.py to PDBs. Useable, but definitely alpha status ;)
- __tpl_XXX.pdb__: PDB template files
- __analysis\PDBs__: Acroform.api PDB files for all AR 10/11/DC versions (english versions only!)

## exploitation/sample_exploits
- __sample_exploit_0write.js__: Javascript code exploiting the 0-DWORD write as described @ SyScan360. The exploit needs to be run with ar_buggery_auto.py (winappdbg-based) or ar_buggery_pykd.py (pykd-based)
- __ar_buggery_auto.py__: winappdbg script which triggers the vulnerable 0-DWORD write
- __ar_buggery_pykd.py__: pykd script which triggers the vulnerable 0-DWORD write
- __Infiltrate_Template.pdf__: Sample PDF which contains 'sample_exploit_0write.js' and executes it when the PDF is opened. Use it together with ar_buggery_auto.py
- __xfa_js_helper.pdf__: PDF which facilitates the execution of JS within XFA context

## slidedecks
- Infiltrate_2016_-_Pwning_Adobe_Reader_with_XFA.pdf/pptx
- SyScan360_2016_-_Pwning_Adobe_Reader_with_XFA.pdf/pptx
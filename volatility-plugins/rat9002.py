'''
@author: Monnappa
Created on Nov 12, 2013
This is a volatility plugin to detect RAT 9002 infection in memory
copy this script to the volatility plugins directory
'''

import volatility.plugins.common as common
import volatility.utils as utils
import volatility.plugins.malware.malfind as malfind
import volatility.win32.tasks as tasks
import volatility.win32.modules as modules
import volatility.plugins.taskmods as taskmods
import struct
import zlib


try:
    import yara
    has_yara = True
except ImportError:
    has_yara = False

rat_9002_sig = {'rat_9002_1': r'rule RAT_9002_1 {strings: $a = "rat_UnInstall" ascii wide condition: $a}',
		'rat_9002_2': r'rule RAT_9002_2 {strings: $b = "McpRoXy.exe" ascii wide condition: $b}',
                'rat_9002_3': r'rule RAT_9002_3 {strings: $c = "SoundMax.dll" ascii wide condition: $c}'
                }

class Rat9002(taskmods.DllList):
    """Detects 9002 RAT infection"""

    def calculate(self):
        if not has_yara:
            debug.error("Please install Yara from code.google.com/p/yara-project")
        addr_space = utils.load_as(self._config)
        rules = yara.compile(sources=rat_9002_sig)
        
        for task in self.filter_tasks(tasks.pslist(addr_space)):
            scanner = malfind.VadYaraScanner(task = task, rules = rules)
            for hit, address in scanner.scan():
                yield (task, address, hit, scanner.address_space.zread(address, 1024))

    def render_text(self, outfd, data):
         for o, addr, hit, content in data:
             outfd.write("Rule: {0}\n".format(hit.rule))
             if o == None:
                outfd.write("Owner: (Unknown Kernel Memory)\n")
                filename = "kernel.{0:#x}.dmp".format(addr)
             elif o.obj_name == "_EPROCESS":
                outfd.write("Owner: Process {0} Pid {1}\n".format(o.ImageFileName,
                    o.UniqueProcessId))
                filename = "process.{0:#x}.{1:#x}.dmp".format(o.obj_offset, addr)
             else:
                outfd.write("Owner: {0}\n".format(o.BaseDllName))
                filename = "kernel.{0:#x}.{1:#x}.dmp".format(o.obj_offset, addr)
                
             outfd.write("".join(
                ["{0:#010x}  {1:<48}  {2}\n".format(addr + o, h,
                ''.join(c)) for o, h, c in
                utils.Hexdump(content[0:128])]))
             outfd.write("\n")
# bstelte (c) 2022 ProcessAnomaly plugin
#
# parts of this code are reused from volatility3 plugin pslist and vadyarascan
# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import datetime
import logging
from typing import Callable, Iterable, List, Type, Tuple
import hashlib, os

from volatility.framework import renderers, interfaces, layers, constants
from volatility.framework.configuration import requirements
from volatility.framework.objects import utility
from volatility.framework.renderers import format_hints
from volatility.framework.symbols import intermed
from volatility.framework.symbols.windows.extensions import pe
from volatility.plugins import timeliner
from volatility.plugins import yarascan

vollog = logging.getLogger(__name__)

try:
    from fuzzywuzzy import fuzz
    fuzzy=1
except:
    print("python modul fuzzywuzzy missing! - similar process name detection disabled")
    fuzzy=0
    
try:
    import sys
    import re
    import codecs
    import kyotocabinet as kc
    nist=1
except:
    print("python modul kyotocabinet missing! - hash set check disabled")
    nist=0
    
    
try:
    import yara
except ImportError:
    vollog.info("Python Yara module not found, plugin (and dependent plugins) not available")
    raise

class ProcessAnomaly(interfaces.plugins.PluginInterface, timeliner.TimeLinerInterface):
    """Lists the processes present in a particular windows memory image."""

    _required_framework_version = (2, 0, 0)
    _version = (2, 0, 0)
    PHYSICAL_DEFAULT = False

    @classmethod
    def get_requirements(cls):
        return [
            requirements.TranslationLayerRequirement(name = 'primary',
                                                     description = 'Memory layer for the kernel',
                                                     architectures = ["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(name = "nt_symbols", description = "Windows kernel symbols"),
            requirements.BooleanRequirement(name = 'physical',
                                            description = 'Display physical offsets instead of virtual',
                                            default = cls.PHYSICAL_DEFAULT,
                                            optional = True),
            requirements.ListRequirement(name = 'pid',
                                         element_type = int,
                                         description = "Process ID to include (all other processes are excluded)",
                                         optional = True),
            requirements.BooleanRequirement(name = 'dump',
                                            description = "Extract listed processes",
                                            default = False,
                                            optional = True),
            requirements.BooleanRequirement(name = 'nist',
                                            description = "Chech hash against NIST Hash Set RDS Modern",
                                            default = False,
                                            optional = True),
            requirements.BooleanRequirement(name = 'yara',
                                            description = "Yarascan",
                                            default = False,
                                            optional = True)
        ]

    @classmethod
    def process_dump(
            cls, context: interfaces.context.ContextInterface, kernel_table_name: str, pe_table_name: str,
            proc: interfaces.objects.ObjectInterface,
            open_method: Type[interfaces.plugins.FileHandlerInterface]) -> interfaces.plugins.FileHandlerInterface:
        """Extracts the complete data for a process as a FileHandlerInterface

        Args:
            context: the context to operate upon
            kernel_table_name: the name for the symbol table containing the kernel's symbols
            pe_table_name: the name for the symbol table containing the PE format symbols
            proc: the process object whose memory should be output
            open_method: class to provide context manager for opening the file

        Returns:
            An open FileHandlerInterface object containing the complete data for the process or None in the case of failure
        """

        file_handle = None
        try:
            proc_layer_name = proc.add_process_layer()
            peb = context.object(kernel_table_name + constants.BANG + "_PEB",
                                 layer_name = proc_layer_name,
                                 offset = proc.Peb)

            dos_header = context.object(pe_table_name + constants.BANG + "_IMAGE_DOS_HEADER",
                                        offset = peb.ImageBaseAddress,
                                        layer_name = proc_layer_name)
            file_handle = open_method("pid.{0}.{1:#x}.dmp".format(proc.UniqueProcessId, peb.ImageBaseAddress))
            for offset, data in dos_header.reconstruct():
                file_handle.seek(offset)
                file_handle.write(data)
        except Exception as excp:
            vollog.debug("Unable to dump PE with pid {}: {}".format(proc.UniqueProcessId, excp))

        return file_handle
        
    @classmethod
    def process_dump_md5(
            cls, context: interfaces.context.ContextInterface, kernel_table_name: str, pe_table_name: str,
            proc: interfaces.objects.ObjectInterface,
            open_method: Type[interfaces.plugins.FileHandlerInterface]) -> interfaces.plugins.FileHandlerInterface:
        """Extracts the complete data for a process as a FileHandlerInterface

        Args:
            context: the context to operate upon
            kernel_table_name: the name for the symbol table containing the kernel's symbols
            pe_table_name: the name for the symbol table containing the PE format symbols
            proc: the process object whose memory should be output
            

        Returns:
            An open FileHandlerInterface object containing the complete data for the process or None in the case of failure
        """

        md5_value = None        
        try:
            proc_layer_name = proc.add_process_layer()
            peb = context.object(kernel_table_name + constants.BANG + "_PEB",
                                 layer_name = proc_layer_name,
                                 offset = proc.Peb)

            dos_header = context.object(pe_table_name + constants.BANG + "_IMAGE_DOS_HEADER",
                                        offset = peb.ImageBaseAddress,
                                        layer_name = proc_layer_name)
            file_handle = open_method("proc_temp.tmp")
            for offset, data in dos_header.reconstruct(): 
                file_handle.seek(offset)
                file_handle.write(data)
            with open("proc_temp.tmp", "rb") as f:
                file_hash = hashlib.md5()
                while chunk := f.read(8192):
                    file_hash.update(chunk)
            md5_value = file_hash.hexdigest().upper()
            os.remove("./proc_temp.tmp")
            
        except Exception as excp:
            vollog.debug("Unable to dump PE with pid {}: {}".format(proc.UniqueProcessId, excp))

        return md5_value

    @staticmethod
    def get_vad_maps(task: interfaces.objects.ObjectInterface) -> Iterable[Tuple[int, int]]:
        """Creates a map of start/end addresses within a virtual address
        descriptor tree.

        Args:
            task: The EPROCESS object of which to traverse the vad tree

        Returns:
            An iterable of tuples containing start and end addresses for each descriptor
        """
        vad_root = task.get_vad_root()
        for vad in vad_root.traverse():
            end = vad.get_end()
            start = vad.get_start()
            yield (start, end - start)

    @classmethod
    def create_pid_filter(cls, pid_list: List[int] = None) -> Callable[[interfaces.objects.ObjectInterface], bool]:
        """A factory for producing filter functions that filter based on a list
        of process IDs.

        Args:
            pid_list: A list of process IDs that are acceptable, all other processes will be filtered out

        Returns:
            Filter function for passing to the `list_processes` method
        """
        filter_func = lambda _: False
        # FIXME: mypy #4973 or #2608
        pid_list = pid_list or []
        filter_list = [x for x in pid_list if x is not None]
        if filter_list:
            filter_func = lambda x: x.UniqueProcessId not in filter_list
        return filter_func

    @classmethod
    def create_name_filter(cls, name_list: List[str] = None) -> Callable[[interfaces.objects.ObjectInterface], bool]:
        """A factory for producing filter functions that filter based on a list
        of process names.

        Args:
            name_list: A list of process names that are acceptable, all other processes will be filtered out

        Returns:
            Filter function for passing to the `list_processes` method
        """
        filter_func = lambda _: False
        # FIXME: mypy #4973 or #2608
        name_list = name_list or []
        filter_list = [x for x in name_list if x is not None]
        if filter_list:
            filter_func = lambda x: utility.array_to_string(x.ImageFileName) not in filter_list
        return filter_func

    @classmethod
    def list_processes(cls,
                       context: interfaces.context.ContextInterface,
                       layer_name: str,
                       symbol_table: str,
                       filter_func: Callable[[interfaces.objects.ObjectInterface], bool] = lambda _: False) -> \
            Iterable[interfaces.objects.ObjectInterface]:
        """Lists all the processes in the primary layer that are in the pid
        config option.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            layer_name: The name of the layer on which to operate
            symbol_table: The name of the table containing the kernel symbols
            filter_func: A function which takes an EPROCESS object and returns True if the process should be ignored/filtered

        Returns:
            The list of EPROCESS objects from the `layer_name` layer's PsActiveProcessHead list after filtering
        """

        # We only use the object factory to demonstrate how to use one
        kvo = context.layers[layer_name].config['kernel_virtual_offset']
        ntkrnlmp = context.module(symbol_table, layer_name = layer_name, offset = kvo)

        ps_aph_offset = ntkrnlmp.get_symbol("PsActiveProcessHead").address
        list_entry = ntkrnlmp.object(object_type = "_LIST_ENTRY", offset = ps_aph_offset)

        # This is example code to demonstrate how to use symbol_space directly, rather than through a module:
        #
        # ```
        # reloff = self.context.symbol_space.get_type(
        #          self.config['nt_symbols'] + constants.BANG + "_EPROCESS").relative_child_offset(
        #          "ActiveProcessLinks")
        # ```
        #
        # Note: "nt_symbols!_EPROCESS" could have been used, but would rely on the "nt_symbols" symbol table not already
        # having been present.  Strictly, the value of the requirement should be joined with the BANG character
        # defined in the constants file
        reloff = ntkrnlmp.get_type("_EPROCESS").relative_child_offset("ActiveProcessLinks")
        eproc = ntkrnlmp.object(object_type = "_EPROCESS", offset = list_entry.vol.offset - reloff, absolute = True)

        for proc in eproc.ActiveProcessLinks:
            if not filter_func(proc):
                yield proc

    def _generator(self):
        pe_table_name = intermed.IntermediateSymbolTable.create(self.context,
                                                                self.config_path,
                                                                "windows",
                                                                "pe",
                                                                class_types = pe.class_types)

        memory = self.context.layers[self.config['primary']]
        if not isinstance(memory, layers.intel.Intel):
            raise TypeError("Primary layer is not an intel layer")

        pid_smss=0
        pid_winlogon=0
        pid_services=0  
        pid_wininit=0
        pid_csrss=0
        ppid_csrss=0
        pid2_csrss=0
        ppid2_csrss=0
        count_services = 0      
        count_lsass = 0
        count_csrss = 0
        fuzzy_value = 0        
        
        try:
            rules = yara.compile(filepath='malware_rules.yar')
        except:
            vollog.info("Python Yara file not found, please start malware_yara_rules.py to download file first.")
            raise
        
        for proc in self.list_processes(self.context,
                                        self.config['primary'],
                                        self.config['nt_symbols'],
                                        filter_func = self.create_pid_filter(self.config.get('pid', None))):

            if not self.config.get('physical', self.PHYSICAL_DEFAULT):
                offset = proc.vol.offset
            else:
                (_, _, offset, _, _) = list(memory.mapping(offset = proc.vol.offset, length = 0))[0]

            file_output = "Disabled"
            if self.config['dump']:
                file_handle = self.process_dump(self.context, self.config['nt_symbols'], pe_table_name, proc,
                                                self.open)
                file_output = "Error outputting file"
                if file_handle:
                    file_handle.close()
                    file_output = str(file_handle.preferred_filename)
                     
            md5_value = self.process_dump_md5(self.context, self.config['nt_symbols'], pe_table_name, proc, self.open)            
            
            #malware yara scan
            yara_value=str()
            if self.config['yara']:                
                layer_name = proc.add_process_layer()
                layer = self.context.layers[layer_name]
                for offset, rule_name, name, value in layer.scan(context = self.context,
                                                                 scanner = yarascan.YaraScanner(rules = rules),
                                                                 sections = self.get_vad_maps(proc)):
                    if rule_name not in yara_value:
                        yara_value = yara_value + rule_name + ","
            else:
                yara_value="deactive"
            
            #ANOMLAY DETECTION for WINDOWS        
            anomaly = "unknown"
            #variables
            proc_name = proc.ImageFileName.cast("string", max_length = proc.ImageFileName.vol.count, errors = 'replace')
            
            #system proc
            if ((proc_name == "System")&(proc.UniqueProcessId==4)&(proc.InheritedFromUniqueProcessId==0)):
                anomaly = "no"
            #memcompression
            if ((proc_name == "MemCompression")&(proc.InheritedFromUniqueProcessId==4)):
                anomaly = "no"   
            #registry (win10)
            if (proc_name == "Registry"):
                if (proc.InheritedFromUniqueProcessId==4):
                    anomaly = "no"
                else:
                    anomaly = "yes - parent pid schould be 4"
            #smss
            if (proc_name == "smss.exe"):
                if (proc.InheritedFromUniqueProcessId==4):
                    anomaly = "no"
                    pid_smss=proc.UniqueProcessId
                else:
                    anomaly = "yes - parent pid schould be 4"
            #csrss
            if (proc_name == "csrss.exe"):
                #win7
                if (proc.InheritedFromUniqueProcessId == pid_smss):
                    anomaly = "no"
                    pid_csrss=proc.UniqueProcessId
                else:
                    #win10
                    if (count_csrss == 0):
                        anomaly = "no"
                        pid_csrss=proc.UniqueProcessId
                        ppid_csrss=proc.InheritedFromUniqueProcessId
                    if (count_csrss == 1):
                        anomaly = "no"
                        pid2_csrss=proc.UniqueProcessId
                        ppid2_csrss=proc.InheritedFromUniqueProcessId
                    count_csrss=count_csrss + 1                    
            #winlogon
            if (proc_name == "winlogon.exe"):                
                if ((proc.InheritedFromUniqueProcessId == pid_smss)|(proc.InheritedFromUniqueProcessId == ppid2_csrss)):
                    anomaly = "no"
                    pid_winlogon=proc.UniqueProcessId  
                else: 
                    anomaly = "yes"
            #wininit
            if (proc_name == "wininit.exe"):
                if ((proc.InheritedFromUniqueProcessId == pid_smss)|(proc.InheritedFromUniqueProcessId == ppid_csrss)):
                    anomaly = "no"
                    pid_wininit=proc.UniqueProcessId 
                else:                
                    anomaly = "yes - parent process should be smss.exe (win 7)"
            #fontdrvhost
            if (proc_name == "fontdrvhost.ex"):
                if ((proc.InheritedFromUniqueProcessId == pid_wininit)|(proc.InheritedFromUniqueProcessId == pid_winlogon)):
                    anomaly = "no"
                else:
                    anomaly = "yes - parent pid should be winlogon or wininit (win10)"
            #lsm
            if (proc_name == "lsm.exe"):
                if (proc.InheritedFromUniqueProcessId == pid_wininit):
                    anomaly = "no"
                else:
                    anomaly = "yes - parent process schould be winint.exe" 
            #services
            if (proc_name == "services.exe"):
                count_services = count_services + 1
                #win 7
                if (proc.InheritedFromUniqueProcessId == pid_winlogon):
                    pid_services=proc.UniqueProcessId
                    anomaly = "no"
                #win 10
                if (proc.InheritedFromUniqueProcessId == pid_wininit):
                    pid_services=proc.UniqueProcessId
                    anomaly = "no"                   
                if (count_services > 1):
                    anomaly = "yes - more than one service process and wrong ppid" 
            #svchost
            if (proc_name == "svchost.exe"):
                if (proc.InheritedFromUniqueProcessId == pid_services):
                    anomaly = "no"
                else:
                    anomaly = "yes - Parent is not services.exe"
            #spoolsv
            if (proc_name == "spoolsv.exe"):
                if (proc.InheritedFromUniqueProcessId == pid_services):
                    anomaly = "no"
                else:
                    anomaly = "yes - Parent is not services.exe"
            #msmpeng
            if (proc_name == "MsMpEng.exe"):
                if (proc.InheritedFromUniqueProcessId == pid_services):
                    anomaly = "no"
                else:
                    anomaly = "yes - Parent is not services.exe"
            #wlms
            if (proc_name == "wlms.exe"):
                if (proc.InheritedFromUniqueProcessId == pid_services):
                    anomaly = "no"
                else:
                    anomaly = "yes - Parent is not services.exe"
            #nissrv            
            if (proc_name == "NisSrv.exe"):
                if (proc.InheritedFromUniqueProcessId == pid_services):
                    anomaly = "no"
                else:
                    anomaly = "yes - Parent is not services.exe"
            #dwm
            if (proc_name == "dwm.exe"):
                if (proc.InheritedFromUniqueProcessId == pid_winlogon):
                    anomaly = "no"
                else:
                    anomaly = "yes - Parent is not winlogon"
            #lsass
            if (proc_name == "lsass.exe"):
                count_lsass = count_lsass + 1
                if ((proc.InheritedFromUniqueProcessId == pid_winlogon)|(proc.InheritedFromUniqueProcessId == pid_wininit)):
                    anomaly = "no"
                else:                    
                    if (count_lsass > 1):
                        anomaly = "yes - more than one lsass process and wrong ppid" 
                        
            #fuzzy similiarity
            if (fuzzy == 1):
                fuzzy_value = 0
                for name in ["System", "Registry", "services.exe", "svchost.exe", "lsass.exe", "wlms.exe", "smss.exe", "csrss.exe", "winlogon.exe", "wininit.exe","dwm.exe","conhost.exe"]:                    
                    fuzzy_temp = fuzz.ratio(proc_name, name)
                    if (fuzzy_value < fuzzy_temp):
                        fuzzy_value = fuzzy_temp           
                if (fuzzy_value == 100):
                    fuzzy_value = "equal"        
                            
                
            #nist hash set check
            #https://github.com/jkjuopperi/nist-hash-check.git
            nist_check="disabled"            
            if ((nist==1)&(self.config['nist'])): 
                nist_check="no_hash"    
                #md5 check            
                unhex = codecs.getdecoder('hex')
                db = kc.DB()
                db.open("NSRLFile.kct", kc.DB.OREADER)
                line=str(md5_value)                
                m = re.search(r'([0-9a-fA-F]{32})', line)                
                if m:
                    hash = unhex(m.group(1))[0]                    
                    nist_check = str(db.get(hash))               
                db.close()

            yield (0, (proc.UniqueProcessId, proc.InheritedFromUniqueProcessId,
                       proc.ImageFileName.cast("string", max_length = proc.ImageFileName.vol.count, errors = 'replace'),
                       format_hints.Hex(offset), str(md5_value), nist_check, str(fuzzy_value), anomaly, str(yara_value)))

    def generate_timeline(self):
        for row in self._generator():
            _depth, row_data = row
            description = "Process: {} {} ({})".format(row_data[0], row_data[2], row_data[3])
            yield (description, timeliner.TimeLinerType.CREATED, row_data[8])
            yield (description, timeliner.TimeLinerType.MODIFIED, row_data[9])    

    def run(self):
        offsettype = "(V)" if not self.config.get('physical', self.PHYSICAL_DEFAULT) else "(P)"

        return renderers.TreeGrid([("PID", int), ("PPID", int), ("ImageFileName", str),
                                   ("Offset{0}".format(offsettype), format_hints.Hex), ("md5sum", str), ("NIST_hash_check", str), ("name_similarity", str), ("anomaly_detection", str), ("yara", str)], self._generator())

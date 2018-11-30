#-------------------------------------------------------------------------------
#
# Copyright (c) 2018, Lasha Khasaia @_qaz_qaz
# Licensed under the GNU GPL v3.
#
#-------------------------------------------------------------------------------

import os
import hashlib
import pickle 

import ida_name
import idautils
import ida_nalt
import ida_dbg
import ida_bytes
import ida_ida
import ida_kernwin
import ida_segment

MD5_hash_data_file = None
SIGNATURE_SIZE = 0x10

def save_x(unique_name=None, start=None, size=None):
      
      ea = ida_kernwin.get_screen_ea()

      # signature
      if not unique_name:
            if not start:
                  seg = ida_segment.getseg(ea)
                  start = seg.start_ea
            sig_bytes = ida_bytes.get_bytes(start, SIGNATURE_SIZE)
            sig_hash = hashlib.md5(sig_bytes).hexdigest()
            unique_name = sig_hash
      
      if not start or not size:
            seg = ida_segment.getseg(ea)
            start = seg.start_ea
            size = seg.size()

      # (start_addr, end_addr, names, comms)
      saved_data = {}
      if MD5_hash_data_file and os.path.isfile(MD5_hash_data_file):
            with open(MD5_hash_data_file, "rb") as ifile:
                  received_data = pickle.loads(ifile.read())
                  if received_data:
                        saved_data = received_data

      # save names (funcs, labels, etc)
      names_addr_name = []
      names = idautils.Names()
      for addr, name in names:
            if start <= addr and addr <= start + size:
                  names_addr_name.append((addr - start, name))

      # save comments
      comms_addr_type_comm = []
      # (addr, TYPE, comment)
      # type 1:comment 2:rpt_comment
      end = start + size
      for i in range(start, end + 1):
            if Comment(i):
                  comms_addr_type_comm.append((i - start, 1, Comment(i)))
            if RptCmt(i):
                  comms_addr_type_comm.append((i - start, 2, RptCmt(i)))
      
      # breakpoints
      bpts_addr_size_type = []
      bpt = ida_dbg.bpt_t()
      for i in range(start, end + 1):
            if ida_dbg.get_bpt(i, bpt):
                  bpts_addr_size_type.append((i - start, bpt.size, bpt.type))

      # SAVE
      saved_data[unique_name] = (start, start + end, names_addr_name, comms_addr_type_comm, bpts_addr_size_type)

      if MD5_hash_data_file:
            with open(MD5_hash_data_file, "wb") as ifile:
                  serial_data = pickle.dumps(saved_data)
                  ifile.write(serial_data)
    
def restore_x(unique_name=None, start=None):

      ea = ida_kernwin.get_screen_ea()

      # signature
      if not unique_name:
            if not start:
                  seg = ida_segment.getseg(ea)
                  start = seg.start_ea
            sig_bytes = ida_bytes.get_bytes(start, SIGNATURE_SIZE)
            sig_hash = hashlib.md5(sig_bytes).hexdigest()
            unique_name = sig_hash

      if not start:
            seg = ida_segment.getseg(ea)
            start = seg.start_ea
      
      if MD5_hash_data_file and os.path.isfile(MD5_hash_data_file):
            with open(MD5_hash_data_file, "rb") as ifile:
                  received_data = pickle.loads(ifile.read())
                  saved_data = received_data
                  
                  # (start_addr, end_addr, names, comms, bpts)
                  if unique_name in saved_data:
                        current_data = saved_data[unique_name]
                        
                        # restore names
                        names = current_data[2]
                        
                        for name in names:
                              # names: (rel_addr, name)
                              ida_name.set_name(start + name[0], name[1])
                        
                        # restore comments
                        # comms: (rel_addr, TYPE, comment)
                        comms = current_data[3]
                        for comm in comms:
                              # 1:MakeComm and 2:MakeRptCmt
                              if comm[1] == 1:
                                    MakeComm(start + comm[0], comm[2])
                              else:
                                    MakeRptCmt(start + comm[0], comm[2])
                        
                        # restore breakpoints
                        # bpts: (rel_addr, size, type)
                        bpts = current_data[4]
                        for bpt in bpts:
                              ida_dbg.add_bpt(start + bpt[0], bpt[1], bpt[2])
    

def main():
    print("Usage:\n\
    save_x(\"unique_name\", start_addr, size) - save names, comments, breakpoints\n\
    restore_x(\"unique_name\", start_addr) - restore names, comments, breakpoints\n\
    Example:\n\t\
    save_x(\"first_shellcode\", 0x12340000, 0x1000)\n\t\
    restore_x(\"first_shellcode\", 0x12340000)\n\t\
    \nBONUS: useful if a process allocated a new segment (e.g. VirtualAlloc) otherwise (HeapAlloc, new, etc.) use the first way\n\t\
    save_x() == save_x(FIRST_0x10_BYTES_HASH_FROM_EA_SEGMENT, START_OF_EA_SEGMENT, SIZEOF_EA_SEGMENT)\n\t\
    restore_x() == restore(FIRST_0x10_BYTES_HASH_FROM_EA_SEGMENT, START_OF_EA_SEGMENT)\n\
    ")
    
    global MD5_hash_data_file
    input_filepath = ida_nalt.get_input_file_path()
    hasher = hashlib.md5()
    with open(input_filepath, 'rb') as afile:
        buf = afile.read()
        hasher.update(buf)
    MD5_hash = hasher.hexdigest() # str
    MD5_hash_data_file = input_filepath + "____rstr___" + MD5_hash

  
if __name__ == "__main__":
  main()
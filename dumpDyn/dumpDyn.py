# -------------------------------------------------------------------------------
#
# Copyright (c) 2018, Lasha Khasaia @_qaz_qaz
# Licensed under the GNU GPL v3.
#
# -------------------------------------------------------------------------------

import os
import hashlib

try:
    import cPickle as pickle
except:
    import pickle

import ida_name
import ida_nalt
import ida_dbg
import ida_bytes
import ida_kernwin
import ida_segment
import ida_auto
import ida_funcs
import idaapi
import idautils

MD5_hash_data_file = None
SIGNATURE_SIZE = 0x10
remove_on_exit_bpts = []

class MyDbgHook(ida_dbg.DBG_Hooks):
    def dbg_process_exit(self, pid, tid, ea, code):
        # remove breakpoints from the dynamically allocated memory
        global remove_on_exit_bpts
        for n in remove_on_exit_bpts:
            ida_dbg.del_bpt(n)
        remove_on_exit_bpts = []
    

class save_class(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        save_x()

        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_FOR_WIDGET if ctx.widget_type == idaapi.BWN_DISASM else idaapi.AST_DISABLE_FOR_WIDGET


class restore_class(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        restore_x()

        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_FOR_WIDGET if ctx.widget_type == idaapi.BWN_DISASM else idaapi.AST_DISABLE_FOR_WIDGET


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

    # save names (func_names, labels, etc)
    # (addr, name, is_code)
    names_addr_name = []
    names = idautils.Names()
    for addr, name in names:
        if start <= addr <= start + size:
            flags = ida_bytes.get_flags(addr)
            names_addr_name.append((addr - start, name, ida_bytes.is_code(flags)))

    # save comments
    comms_addr_type_comm = []
    # (addr, TYPE, comment)
    # type 0:comment 1:rpt_comment
    end = start + size
    for i in range(start, end + 1):
        if ida_bytes.get_cmt(i, 0):  # 0 Comment
            comms_addr_type_comm.append((i - start, 0, ida_bytes.get_cmt(i, 0)))
        if ida_bytes.get_cmt(i, 1):  # 1 RptCmt
            comms_addr_type_comm.append((i - start, 1, ida_bytes.get_cmt(i, 1)))

    # breakpoints
    bpts_addr_size_type = []
    bpt = ida_dbg.bpt_t()
    global remove_on_exit_bpts
    for i in range(start, end + 1):
        if ida_dbg.get_bpt(i, bpt):
            bpts_addr_size_type.append((i - start, bpt.size, bpt.type))
            remove_on_exit_bpts.append(i)

    # functions
    funcs_addr = []
    flag = ida_bytes.get_flags(start)
    if ida_bytes.is_func(flag):
        funcs_addr.append(0) # start addr
    next_func =  ida_funcs.get_next_func(start)
    while next_func:
        funcs_addr.append(next_func.start_ea - start)
        next_func = ida_funcs.get_next_func(next_func.start_ea)


    # SAVE
    saved_data[unique_name] = (start, start + end, names_addr_name, comms_addr_type_comm, bpts_addr_size_type, funcs_addr)

    if MD5_hash_data_file:
        with open(MD5_hash_data_file, "wb") as ifile:
            serial_data = pickle.dumps(saved_data)
            ifile.write(serial_data)
            print("dumpDyn::save:\n\
            Name: {}\n\
            Start address: {}".format(unique_name, hex(start)))


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

            print("dumpDyn::restore\n\
            Name: {}\n\
            Restore address: {}\n".format(unique_name, hex(start)))

            # (start_addr, end_addr, names, comms, bpts, funcs)
            if unique_name in saved_data:
                current_data = saved_data[unique_name]

                # restore names
                names = current_data[2]

                for name in names:
                    # names: (rel_addr, name, is_code)
                    ida_name.set_name(start + name[0], name[1])
                    flags = ida_bytes.get_flags(start + name[0])
                    if name[2] and not ida_bytes.is_code(flags):
                        ida_auto.auto_make_code(start + name[0])

                # restore comments
                # comms: (rel_addr, TYPE, comment)
                comms = current_data[3]
                for comm in comms:
                    # 0:MakeComm and 1:MakeRptCmt
                    ida_bytes.set_cmt(start + comm[0], comm[2], comm[1])

                # restore breakpoints
                # bpts: (rel_addr, size, type)
                bpts = current_data[4]
                for bpt in bpts:
                    ida_dbg.add_bpt(start + bpt[0], bpt[1], bpt[2])

                # restore functions
                funcs_addr = current_data[5]
                for addr in funcs_addr:
                    ida_auto.auto_make_proc(start + addr) # make code & func


def main():
    print("\nUsage:\n\
      save_x(\"unique_name\", start_addr, size) - save names, comments, breakpoints, functions\n\
      restore_x(\"unique_name\", start_addr) - restore names, comments, breakpoints, functions\n\
      Example:\n\t\
      save_x(\"first_shellcode\", 0x12340000, 0x1000)\n\t\
      restore_x(\"first_shellcode\", 0x12340000)\n\t\
      save_x(\"f1\", here(), 0x1000)\n\t\
      restore_x(\"f1\", here())\n\
      \nBONUS: useful if a process allocated a new segment (e.g. VirtualAlloc) otherwise (HeapAlloc, new, etc.) use the first way\n\t\
      save_x() == save_x(FIRST_0x10_BYTES_HASH_FROM_EA_SEGMENT, START_OF_EA_SEGMENT, SIZEOF_EA_SEGMENT)\n\t\
      restore_x() == restore(FIRST_0x10_BYTES_HASH_FROM_EA_SEGMENT, START_OF_EA_SEGMENT)\n\
      ")

    icon_data_save = "".join([
        "\x89\x50\x4E\x47\x0D\x0A\x1A\x0A\x00\x00\x00\x0D\x49\x48\x44\x52\x00\x00\x00\x10\x00\x00\x00\x10\x04\x03\x00"
        "\x00\x00\xED\xDD\xE2\x52\x00\x00\x00\x1E\x50\x4C\x54\x45\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xB7\x28\x6F\x6A\x00\x00\x00\x09\x74\x52"
        "\x4E\x53\x00\xE0\x08\xB8\xD0\x58\x98\x85\x25\x4C\x7E\x68\xAA\x00\x00\x00\x49\x49\x44\x41\x54\x08\xD7\x63\x60"
        "\x60\x60\x99\x39\xD3\x01\x48\x11\xC3\xE0\x08\x0D\x9C\x39\x53\x34\xB4\x81\x81\xC9\x72\x26\x10\x4C\x56\x60\x60"
        "\x50\x06\x31\x8C\x80\x72\x40\x21\xB0\x00\x50\x08\x2C\x00\x16\x02\x09\x80\x85\x80\x02\x10\x21\x90\x00\x02\xB0"
        "\x0B\x82\x41\x01\x03\xDB\x4C\x30\x48\x00\x00\xA9\xC1\x1A\x09\x2E\x8B\x71\x91\x00\x00\x00\x00\x49\x45\x4E\x44"
        "\xAE\x42\x60\x82 "
    ])
    icon_data_restore = "".join([
        "\x89\x50\x4E\x47\x0D\x0A\x1A\x0A\x00\x00\x00\x0D\x49\x48\x44\x52\x00\x00\x00\x10\x00\x00\x00\x10\x04\x03\x00"
        "\x00\x00\xED\xDD\xE2\x52\x00\x00\x00\x1E\x50\x4C\x54\x45\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xB7\x28\x6F\x6A\x00\x00\x00\x09\x74\x52"
        "\x4E\x53\x00\x81\xE0\xD0\x98\x40\xEC\x34\x2D\xD9\x04\x16\x77\x00\x00\x00\x46\x49\x44\x41\x54\x08\xD7\x63\x00"
        "\x02\x46\x01\x06\x08\x90\x9C\x08\xA1\x19\x67\xCE\x14\x80\x08\xCC\x9C\x39\x11\x2A\x00\x14\x82\x08\x80\x85\x38"
        "\x5C\xDC\x66\xCE\x4C\x71\x69\x00\x0A\x31\xCF\x9C\x69\x00\xA4\x88\x63\xB0\x87\x86\x16\x30\x20\x01\x46\x25\x30"
        "\x10\x60\x60\x99\x09\x06\x0E\x00\xB5\x68\x19\x1B\xBF\xF3\x8F\x71\x00\x00\x00\x00\x49\x45\x4E\x44\xAE\x42\x60"
        "\x82 "
    ])

    act_icon_save = idaapi.load_custom_icon(data=icon_data_save, format="png")
    act_icon_restore = idaapi.load_custom_icon(data=icon_data_restore, format="png")

    act_name_save = "dumpDyn_save:action"
    act_name_restore = "dumpDyn_restore:action"
    if idaapi.register_action(idaapi.action_desc_t(
            act_name_save,
            "save_x",
            save_class(),
            None,
            "save_x",
            act_icon_save)):

        # Insert the action in a toolbar
        idaapi.attach_action_to_toolbar("DebugToolBar", act_name_save)

        if idaapi.register_action(idaapi.action_desc_t(
                act_name_restore,
                "restore_x",
                restore_class(),
                None,
                "restore_x",
                act_icon_restore)):
            # Insert the action in a toolbar
            idaapi.attach_action_to_toolbar("DebugToolBar", act_name_restore)

    else:
        idaapi.unregister_action(act_name_save)
        idaapi.unregister_action(act_name_restore)

    global MD5_hash_data_file
    input_filepath = ida_nalt.get_input_file_path()
    hasher = hashlib.md5()
    with open(input_filepath, 'rb') as afile:
        buf = afile.read()
        hasher.update(buf)
    MD5_hash = hasher.hexdigest()  # str
    MD5_hash_data_file = input_filepath + "____dumpDyn___" + MD5_hash

if __name__ == "__main__":
    # Remove an existing debug hook
    try:
        if debughook:
            debughook.unhook()
    except:
        pass
    debughook = MyDbgHook()
    debughook.hook()

    main()

import gdb
import time
from datetime import datetime

MAGIC_CONSTANT = 153823877865751
HEADER_SIZE = 32
LOG_ENTRY_SIZE = 32
type_list = ["char", "uint64_t", "int32_t"]
LOG_SIZE = 2*4096
PATCH_BACKUP_SIZE = 4096

def find_object_static(symbol_name: str, objfile_name: str) -> gdb.Value:
    try:
        objfile = gdb.lookup_objfile(objfile_name)
        symbol = objfile.lookup_static_symbol(symbol_name).value()
    except:
        raise gdb.GdbError("Couldn't find " + symbol_name + "in object file " + objfile_name + ".")
    else:
        return symbol

def find_object_obj(symbol_name: str, objfile_name: str) -> gdb.Value:
    try:
        objfile = gdb.lookup_objfile(objfile_name)
        symbol = objfile.lookup_global_symbol(symbol_name).value()
    except:
        raise gdb.GdbError("Couldn't find " + symbol_name + "in object file " + objfile_name + ".")
    else:
        return symbol

def find_object(symbol_name: str) -> gdb.Value:
    try:
        symbol = gdb.parse_and_eval(symbol_name)
    except:
        raise gdb.GdbError("Couldn't find " + symbol_name + ".")
    else:
        return symbol

class struct_header:
    def __init__(self, magic: int, libhandle: int, refcount: int, contains_log: bool, log_entries_count: int, patch_data_array_len: int, commands_len: int):
        self.magic = magic
        self.libhandle = libhandle
        self.refcount = refcount
        self.contains_log = contains_log
        #log entries count
        self.log_entries_count = log_entries_count
        #number of bytes ocuppied by membackup
        self.patch_data_array_len = patch_data_array_len
        self.commands_len = commands_len

    def print(self):
        print(self.magic)
        print(self.libhandle)
        print(self.refcount)
        print(self.contains_log)
        print(self.log_entries_count)
        print(self.patch_data_array_len)
        print(self.commands_len)

def read_header(objfile_path: str) -> struct_header:
    inferior = gdb.selected_inferior()
    patchlib = gdb.lookup_objfile(objfile_path)
    if patchlib is None:
        return None

    try:
        header_addr = int(find_object_static("patch_header", objfile_path).address)
    except:
        return None
    buffer = inferior.read_memory(header_addr, HEADER_SIZE)
    magic = int.from_bytes(buffer[:8], "little")
    if magic != MAGIC_CONSTANT:
        return None
    libhandle = int.from_bytes(buffer[8:16], "little")
    refcount = int.from_bytes(buffer[16:18], "little")
    contains_log = int.from_bytes(buffer[18:20], "little")
    if contains_log == 0:
        contains_log_bool = False
    elif contains_log == 1:
        contains_log_bool = True
    else:
        raise gdb.GdbError("Got wrong value for contains_log value.")
    log_entries_count = int.from_bytes(buffer[20:24], "little")
    patch_data_array_len = int.from_bytes(buffer[24:28], "little")
    commands_len = int.from_bytes(buffer[28:32], "little")
    return struct_header(magic, libhandle, refcount, contains_log, log_entries_count, patch_data_array_len, commands_len)

def write_header(objfile_path: str, header: struct_header) -> None:
    if header.magic != MAGIC_CONSTANT:
        raise gdb.GdbError("Got wrong value of magic constant while trying to write header.")

    header_addr = int(find_object_static("patch_header", objfile_path).address)

    buffer = bytearray()
    buffer.extend(header.magic.to_bytes(8, "little"))
    buffer.extend(header.libhandle.to_bytes(8, "little"))
    buffer.extend(header.refcount.to_bytes(2, "little"))
    if header.contains_log:
        tmp = 1
    else:
        tmp = 0
    buffer.extend(tmp.to_bytes(2, "little"))
    buffer.extend(header.log_entries_count.to_bytes(4, "little"))
    buffer.extend(header.patch_data_array_len.to_bytes(4, "little"))
    buffer.extend(header.commands_len.to_bytes(4, "little"))

    inferior = gdb.selected_inferior()
    inferior.write_memory(header_addr, buffer, len(buffer))

class struct_log_entry:
    def __init__(self, target_func_ptr: int,
        patch_func_ptr: int,
        patch_type: str,
        timestamp: int,
        path_offset: int,
        is_active: bool,
        membackup_offset: int,
        path_len: int,
        membackup_len: int):
        self.target_func_ptr = target_func_ptr
        self.patch_func_ptr = patch_func_ptr
        if patch_type != "O" and patch_type != "L":
            raise gdb.GdbError("Got wrong patch type.")
        self.patch_type = patch_type
        self.timestamp = timestamp
        self.path_offset = path_offset
        self.is_active = is_active
        self.membackup_offset = membackup_offset
        self.path_len = path_len
        self.membackup_len = membackup_len

    def to_string(self, master_lib_path: str):
        master_lib = gdb.lookup_objfile(master_lib_path)
        backup_ptr = int(find_object_static("patch_backup", master_lib_path).address)
        backup_ptr += self.path_offset
        path = bytearray(gdb.selected_inferior().read_memory(backup_ptr, self.path_len)).decode("ascii")
        tmp = " "
        if self.is_active:
            tmp = "* "
        return "".join([tmp, str(datetime.fromtimestamp(self.timestamp)), ": ", hex(self.target_func_ptr), " -> ", path, ":", hex(self.patch_func_ptr)])

def read_log_entry(objfile_name: str, index: int) -> struct_log_entry:
    objfile = gdb.lookup_objfile(objfile_name)
    if objfile is None:
        return None
    header = read_header(objfile_name)
    #TODO
    if header.magic != MAGIC_CONSTANT or header.contains_log == False:
        return None
    if index*LOG_ENTRY_SIZE >= LOG_SIZE:
        return None

    log_address = int(find_object_static("patch_log", objfile_name).address)
    log_address += index*LOG_ENTRY_SIZE
    inferior = gdb.selected_inferior()
    buffer = bytearray(inferior.read_memory(log_address, LOG_ENTRY_SIZE))
    target_func_ptr = int.from_bytes(buffer[0:8], "little")
    patch_func_ptr = int.from_bytes(buffer[8:16], "little")
    patch_type = int.from_bytes(buffer[16:17], "little")
    if patch_type == 0:
        patch_type_str = "O"
    else:
        patch_type_str = "L"
    timestamp = int.from_bytes(buffer[17:21], "little")
    path_offset = int.from_bytes(buffer[21:25], "little")
    is_active_int = int.from_bytes(buffer[25:27], "little")
    if is_active_int == 0:
        is_active = False
    elif is_active_int == 1:
        is_active = True
    else:
        raise gdb.GdbError("Got wrong value of is_active")

    membackup_offset = int.from_bytes(buffer[27:29], "little")
    path_len = int.from_bytes(buffer[29:31], "little")
    membackup_len = int.from_bytes(buffer[31:32], "little")
    return struct_log_entry(target_func_ptr, patch_func_ptr, patch_type_str, timestamp, path_offset, is_active, membackup_offset, path_len, membackup_len)

def write_log_entry(master_lib: str, log_entry: struct_log_entry, index: int) -> None:
    objfile = gdb.lookup_objfile(master_lib)
    log_ptr = int(objfile.lookup_static_symbol("patch_log").value().address)
    log_ptr += index*LOG_ENTRY_SIZE

    log_entry_buf = bytearray()
    log_entry_buf.extend(log_entry.target_func_ptr.to_bytes(8, "little"))
    log_entry_buf.extend(log_entry.patch_func_ptr.to_bytes(8, "little"))
    if log_entry.patch_type == "O":
        tmp = 0
    elif log_entry.patch_type == "L":
        tmp = 1
    else:
        tmp = 255

    log_entry_buf.extend(tmp.to_bytes(1, "little"))
    log_entry_buf.extend(log_entry.timestamp.to_bytes(4, "little"))
    log_entry_buf.extend(log_entry.path_offset.to_bytes(4, "little"))
    if log_entry.is_active:
        tmp = 1
    else:
        tmp = 0
    log_entry_buf.extend(tmp.to_bytes(2, "little"))
    log_entry_buf.extend(log_entry.membackup_offset.to_bytes(2, "little"))
    log_entry_buf.extend(log_entry.path_len.to_bytes(2, "little"))
    log_entry_buf.extend(log_entry.membackup_len.to_bytes(1, "little"))
    gdb.selected_inferior().write_memory(log_ptr, log_entry_buf, len(log_entry_buf))

def get_last_log_entry(master_lib: str) -> struct_log_entry:
    hdr = read_header(master_lib)
    return read_log_entry(master_lib, hdr.log_entries_count - 1)

class struct_patch_backup:
    def __init__(self, path: str, membackup: bytearray):
        self.path = path
        self.membackup = membackup

    def size(self) -> int:
        result = 0
        if self.path is not None:
            result += len(self.path)
        if self.membackup is not None:
            result += len(self.membackup)
        return result

def read_log_entry_data(objfile_path: str, log_entry: struct_log_entry) -> struct_patch_backup:
    path = None
    membackup = None
    log_data_ptr = int(find_object_static("patch_backup", objfile_path).address)
    if log_entry.path_len != 0:
        path = bytearray(gdb.selected_inferior().read_memory(log_data_ptr + log_entry.path_offset, log_entry.path_len)).decode("ascii")
    if log_entry.membackup_len != 0:
        membackup = bytearray(gdb.selected_inferior().read_memory(log_data_ptr + log_entry.membackup_offset, log_entry.membackup_len))
    return struct_patch_backup(path, membackup)

def add_log_entry(objfile_path: str, log_entry: struct_log_entry, patch_backup: struct_patch_backup) -> None:
    header = read_header(objfile_path)
    index = header.log_entries_count
    patch_backup_ptr = int(find_object_static("patch_backup", objfile_path).address)
    log_size = header.log_entries_count*LOG_ENTRY_SIZE
    backup_size = header.patch_data_array_len
    patch_backup_ptr += backup_size
    #TODO at least print an error message
    if log_size + LOG_ENTRY_SIZE > LOG_SIZE or backup_size + patch_backup.size() > PATCH_BACKUP_SIZE:
        return None
    offset = header.patch_data_array_len
    #update header
    header.log_entries_count += 1
    header.patch_data_array_len += patch_backup.size()
    write_header(objfile_path, header)

    inferior = gdb.selected_inferior()
    if patch_backup.path is not None:
        backup_buf = bytearray(patch_backup.path.encode())
        inferior.write_memory(patch_backup_ptr, backup_buf, len(backup_buf))
        patch_backup_ptr += len(backup_buf)
        log_entry.path_offset = backup_size
        backup_size += len(backup_buf)

    if patch_backup.membackup is not None:
        inferior.write_memory(patch_backup_ptr, patch_backup.membackup, len(patch_backup.membackup))
        log_entry.membackup_offset = backup_size

    write_log_entry(objfile_path, log_entry, index)

#TODO also sets log is_active flag
def find_last_patch(master_lib: str, func_address: int) -> str:
    hdr = read_header(master_lib)
    i = hdr.log_entries_count - 1
    result = None
    while i >= 0:
        entry = read_log_entry(master_lib, i)
        if entry is None:
            return None
        if entry.is_active and entry.target_func_ptr == func_address:
            result = read_log_entry_data(master_lib, entry).path
            entry.is_active = False
            write_log_entry(master_lib, entry, i)
        i -= 1
    return result

def find_first_patch(master_lib: str, func_address: int) -> struct_log_entry:
    hdr = read_header(master_lib)
    for i in range(hdr.log_entries_count):
        entry = read_log_entry(master_lib, i)
        if entry is None:
            return None
        if entry.target_func_ptr == func_address:
            return entry
    return None

def copy_log(dest: str, src: str):
    src_log = int(find_object_static("patch_log", src).address)
    src_backup = int(find_object_static("patch_backup", src).address)
    dest_log = int(find_object_static("patch_log", dest).address)
    dest_backup = int(find_object_static("patch_backup", dest).address)
    src_hdr = read_header(src)
    dest_hdr = read_header(dest)
    dest_hdr.contains_log = True
    dest_hdr.log_entries_count = src_hdr.log_entries_count
    dest_hdr.patch_data_array_len = src_hdr.patch_data_array_len
    inferior = gdb.selected_inferior()
    log_buffer = bytearray(inferior.read_memory(src_log, src_hdr.log_entries_count*LOG_ENTRY_SIZE))
    backup_buffer = bytearray(inferior.read_memory(src_backup, src_hdr.patch_data_array_len))
    inferior.write_memory(dest_log, log_buffer, len(log_buffer))
    inferior.write_memory(dest_backup, backup_buffer, len(backup_buffer))

def close_lib(lib: str):
    hdr = read_header(lib)
    if hdr.contains_log:
        hdr.contains_log = False
        write_header(lib, hdr)
        for objfile in gdb.objfiles():
            try:
                header = read_header(objfile.filename)
            except:
                continue
            if header is None:
                continue
            if header.magic == MAGIC_CONSTANT:
               copy_log(objfile.filename, lib)
    dlclose = find_object("dlclose")
    dlclose(hdr.libhandle)

def decrease_refcount(lib: str):
    hdr = read_header(lib)
    hdr.refcount -= 1
    write_header(lib, hdr)
    if hdr.refcount <= 0:
        close_lib(lib)

def steal_refcount(master_lib: str, func_address: int, current_lib: str):
    lib = find_last_patch(master_lib, func_address)
    if lib is not None:
        hdr = read_header(lib)
        hdr.refcount -= 1
        write_header(lib, hdr)

    current = read_header(current_lib)
    current.refcount += 1
    write_header(current_lib, current)

def find_master_lib() -> str:
    for objfile in gdb.objfiles():
        try:
            header = read_header(objfile.filename)
        except:
            continue
        if header is None:
            continue
        if header.contains_log:
            return objfile.filename
    return None

class AbsoluteTrampoline:
    def __init__(self):
       self.trampoline = bytearray.fromhex("49 bb 00 00 00 00 00 00 00 00 41 ff e3")

    def size(self) -> int:
        return 13

    def complete_address(self, addr: bytearray):
        for i in range(8):
            self.trampoline[i+2] = addr[i]

    def write_trampoline(self, address: gdb.Value):
        inferior = gdb.selected_inferior()
        inferior.write_memory(address, self.trampoline, 13)

    def write_trampoline_int(self, address: int):
        inferior = gdb.selected_inferior()
        inferior.write_memory(address, self.trampoline, 13)

class PatchStrategy:
    def __init__(self, lib_handle: gdb.Value, dlclose: gdb.Value, path: str, target_func: str, patch_func: str):
        self.lib_handle = lib_handle
        self.dlclose = dlclose
        self.path = path
        self.target_func = target_func
        self.patch_func = patch_func

    def do_patch(self, master_lib: str, path_offset: int, path_len: int, membackup_offset: int, membackup_len: int):
        pass
    
    def clean(self):
        pass

class PatchOwnStrategy (PatchStrategy):
    def __init__(self, lib_handle: gdb.Value, dlclose: gdb.Value, path: str,  target_func: str, patch_func: str):
        super().__init__(lib_handle, dlclose, path, target_func, patch_func)

    def do_patch(self, master_lib: str, path_offset: int, path_len: int, membackup_offset: int, membackup_len: int):
        try:
            target_addr = find_object(self.target_func)
            self.target_addr = int(target_addr.cast(gdb.lookup_type("uint64_t")))
        except:
            self.clean()
            raise gdb.GdbError("Couldn't find target function symbol.")

        #control flow must not be where the trampoline is about to be inserted
        #TODO control flow must not be in the function, it may lead to crash
        tmp = int(target_addr.cast(gdb.lookup_type("uint64_t")))
        rip = int(gdb.parse_and_eval("$rip").cast(gdb.lookup_type("uint64_t")))
        if rip >= tmp and rip < tmp + 13:
            self.clean()
            raise gdb.GdbError("The code segment where the trampoline is about to be inserted is being executed.")

        #try to resolve symbol for patch function
        try:
            patch_addr = find_object_static(self.patch_func, self.path).cast(gdb.lookup_type("uint64_t"))
        except:
            raise gdb.GdbError("Couldn't find " + self.patch_func  + " symbol.")
        patch_addr_arr = int(patch_addr).to_bytes(8, byteorder = "little")

        #steal refcount
        steal_refcount(master_lib, self.target_addr, self.path)

        #write to log
        entry = struct_log_entry(self.target_addr, int(patch_addr), "O", int(time.time()), 0, True, 0, 0, 0)
        backup = struct_patch_backup(None, None)
        if path_offset != -1:
            entry.path_offset = path_offset
            entry.path_len = path_len
        else:
            backup.path = self.path
            entry.path_len = len(self.path)

        tmp = find_first_patch(master_lib, self.target_addr)
        if tmp is None:
            backup.membackup = bytearray(gdb.selected_inferior().read_memory(target_addr, 13))
            entry.membackup_len = len(backup.membackup)
        else:
            entry.membackup_offset = tmp.membackup_offset
            entry.membackup_len = tmp.membackup_len
        add_log_entry(master_lib, entry, backup)

        #write trampoline
        trampoline = AbsoluteTrampoline()
        inferior = gdb.selected_inferior()
        self.membackup = bytearray(inferior.read_memory(target_addr.cast(gdb.lookup_type("char").pointer()), trampoline.size()))
        trampoline.complete_address(patch_addr_arr)
        #cast target_addr to char *
        trampoline.write_trampoline(target_addr.cast(gdb.lookup_type("char").pointer()))

    def clean(self):
        self.dlclose(self.lib_handle)

class PatchLibStrategy (PatchStrategy):
    def __init__(self, lib_handle: gdb.Value, dlclose: gdb.Value, path: str, target_func: str, patch_func: str):
        super().__init__(lib_handle, dlclose, path, target_func, patch_func)

    def do_patch(self, master_lib: str, path_offset: int, path_len: int, membackup_offset: int, membackup_len: int):
        #find target and patch functions
        try:
            target = "'" + self.target_func + "@plt'"
            target = find_object(target)
            target_ptr = int(target.cast(gdb.lookup_type("uint64_t")))
            patch = find_object_static(self.patch_func, self.path)
            patch = patch.cast(gdb.lookup_type("char").pointer())
            patch_ptr = int(patch.cast(gdb.lookup_type("uint64_t")))
        except:
            self.dlclose(self.lib_handle)

        #fetch relative offset
        target = target.cast(gdb.lookup_type("char").pointer())
        target += 2
        target = target.cast(gdb.lookup_type("int32_t").pointer())
        relative_addr = target.dereference()

        #fetch next instruction's address
        target = target.cast(gdb.lookup_type("char").pointer())
        next_instruction = target + 4

        #calculate got.plt entry
        addr_got = next_instruction.cast(gdb.lookup_type("char").pointer())
        addr_got += relative_addr
        self.addr_got = int(addr_got.cast(gdb.lookup_type("uint64_t")))
        patch_arr = int(patch).to_bytes(8, byteorder = "little")

        #steal refcount
        steal_refcount(master_lib, target_ptr, self.path)

        #write to log
        entry = struct_log_entry(self.target_ptr, patch_ptr, "L", int(time.time()), 0, True, 0, 0, 0)
        backup = struct_patch_backup(None, None)
        if path_offset != -1:
            entry.path_offset = path_offset
            entry.path_len = path_len
        else:
            backup.path = self.path
            entry.path_len = len(self.path)

        tmp = find_first_patch(master_lib, self.target_addr)
        if tmp is None:
            backup.membackup = bytearray(gdb.selected_inferior().read_memory(self.addr_got, 8))
            entry.membackup_len = len(backup.membackup)
        else:
            entry.membackup_offset = tmp.membackup_offset
            entry.membackup_len = tmp.membackup_len
        add_log_entry(master_lib, entry, backup)

        inferior = gdb.selected_inferior()
        #backup data
        self.membackup = bytearray(inferior.read_memory(addr_got, 8))
        #write patch function address
        inferior.write_memory(addr_got, patch_arr, 8)

    def clean(self):
        pass

class Patch (gdb.Command):
    "Patch functions."

    type_dict = {}

    def __init__(self):
        super(Patch, self).__init__("patch", gdb.COMMAND_USER)

    def extract_patch_metadata(self, objfile: str) -> list[list[str]]:
        try:
            patchlib = gdb.lookup_objfile(objfile)
        except:
            print("error in extract_patch_meta")
        header = read_header(objfile)
        if header is None:
            #TODO
            raise gdb.GdbError("Couldn't find header.")
        commands_len = header.commands_len
        commands = int(patchlib.lookup_static_symbol("patch_commands").value().address)

        inferior = gdb.selected_inferior()
        items = inferior.read_memory(commands, commands_len).tobytes().decode().split(";")
        result = []
        for item in items:
            #TODO
            if not item:
                continue
            result.append(item.split(":"))
        return result

    def is_patchable(self):
        try:
            #check if essential types are present in the target process
            for t in type_list:
                self.type_dict[t] = gdb.lookup_type(t)
        except:
            raise gdb.GdbError("Required types were not supported.")
 
    #TODO check -> magic const must be equal to the one defined in C header
    def load_patch_lib(self, path: str):
        self.dlopen_ret = self.dlopen_addr(path, 2)
        if self.dlopen_ret == 0:
            raise gdb.GdbError("Couldn't open the patch library.")
        header = read_header(path)
        if header is None or header.magic != MAGIC_CONSTANT:
            self.dlclose_addr(self.dlopen_ret)
            gdb.write("Object file " + path + " has a wrong format.")
        header.libhandle = int(self.dlopen_ret.cast(gdb.lookup_type("uint64_t")))
        write_header(path, header)
        
    def complete(self, text, word):
        return gdb.COMPLETE_FILENAME

    def invoke(self, arg, from_tty):
        self.type_dict.clear()
        argv = gdb.string_to_argv(arg)
        if len(argv) != 1:
            raise gdb.GdbError("patch takes one parameter")

        #find necessary objects
        self.dlopen_addr = find_object("dlopen")
        self.dlclose_addr = find_object("dlclose")
        self.is_patchable()

        self.load_patch_lib(argv[0])
        metadata = self.extract_patch_metadata(argv[0])
        master_lib = find_master_lib()
        if master_lib is None:
            master_lib = argv[0]
        tmp = read_header(master_lib)
        tmp.contains_log = True
        write_header(master_lib, tmp)
        counter = 0

        for patch in metadata:
            target_func = patch[1]
            patch_func = patch[2]

            if patch[0] == 'O':
                self.strategy = PatchOwnStrategy(self.dlopen_ret, self.dlclose_addr, argv[0], target_func, patch_func)
            elif patch[0] == 'L':
                self.strategy = PatchLibStrategy(self.dlopen_ret, self.dlclose_addr, argv[0], target_func, patch_func)
            else:
                raise gdb.GdbError("Patching own and library functions is only supported for now.")

            if counter == 0:
                self.strategy.do_patch(master_lib, -1, 0, -1, 0)
                first_entry = get_last_log_entry(master_lib)
            else:
                self.strategy.do_patch(master_lib, first_entry.path_offset, first_entry.path_len, -1, 0)
            counter += 1

class PatchLog(gdb.Command):
    def __init__(self):
        super(PatchLog, self).__init__("patch-log", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        argv = gdb.string_to_argv(arg)
        if len(argv) != 0:
            raise gdb.GdbError("patch-log takes no parameters")

        print("[0] revert")

        master_lib_path = find_master_lib()
        header = read_header(master_lib_path)
        for i in range(header.log_entries_count):
            entry = read_log_entry(master_lib_path, i)
            print("[" + str(i+1) + "]" + entry.to_string(master_lib_path))

#WARNING!!! sets found library as inactive
#TODO poor design
def find_active_entry(master_lib: str, func_address: int) -> struct_log_entry:
    size = read_header(master_lib).log_entries_count
    for i in range(size):
        entry = read_log_entry(master_lib, i)
        #TODO when applying a patch you must scan if a function has been patched to assign the corresponding memory backup
        if entry.target_func_ptr == func_address and entry.is_active:
            entry.is_active = False
            write_log_entry(master_lib, entry, i)
            return entry
    return None

class ReapplyPatch(gdb.Command):
    def __init__(self):
        super(ReapplyPatch, self).__init__("patch-reapply", gdb.COMMAND_USER)

    def revert(self, argv: list[str], master_lib: str):
        i = 1
        while i < len(argv):
            try:
                function_address = int(find_object(argv[i]).cast(gdb.lookup_type("uint64_t")))
            except:
                function_address = int(find_object("'" + argv[i] + "@plt'").cast(gdb.lookup_type("uint64_t")))
            entry = find_active_entry(master_lib, function_address)
            if entry is None:
                print("Nothing to revert.")
            backup = read_log_entry_data(master_lib, entry)
            membackup = backup.membackup
            inferior = gdb.selected_inferior()
            if membackup is None:
                raise gdb.GdbError("Fatal error, couldn't find membackup.")
            if entry.patch_type == "O":
                #TODO only absolute trampoline for now
                inferior.write_memory(function_address, membackup, len(membackup))
            elif entry.patch_type == "L":
                instruction = function_address + 2
                relative_offset = int.from_bytes(bytearray(inferior.read_memory(instruction, 4)), "little")
                got_entry = function_address + 6 + relative_offset
                inferior.write_memory(got_entry, membackup, len(membackup))

            #decrease refcount
            #decrease_refcount(backup.path)
            hdr = read_header(backup.path)
            hdr.refcount -= 1
            write_header(backup.path, hdr)
            i += 1

    def invoke(self, arg, from_tty):
        argv = gdb.string_to_argv(arg)
        if len(arg) < 1:
           raise gdb.GdbError("patch-reapply takes one parameter")
        master_lib = find_master_lib()
        if master_lib is None:
            raise gdb.GdbError("Couldn't find the log, master library is not present.")

        index = int(argv[0])
        if index == 0:
            #TODO revert
            self.revert(argv, master_lib)
            return

        index -= 1

        log_entry = read_log_entry(master_lib, index)
        if log_entry is None:
            raise gdb.GdbError("The log entry does not exist.")

        #nothing to do
        if log_entry.is_active:
            return

        #check if the library is still open
        data = read_log_entry_data(master_lib, log_entry)
        if data.path is None:
            gdb.GdbError("Failed to fetch patchlib path.")
        if gdb.lookup_objfile(data.path) is None:
            #the lib is unmapped
            raise gdb.GdbError("The library has been closed. Cannot apply the patch.")
        if log_entry.patch_type == "O":
            trampoline = AbsoluteTrampoline()
            trampoline.complete_address(bytearray(log_entry.patch_func_ptr.to_bytes(8, "little")))
            trampoline.write_trampoline_int(log_entry.target_func_ptr)
        elif log_entry.patch_type == "L":
            instruction_ptr = log_entry.target_func_ptr + 2
            inferior = gdb.selected_inferior()
            relative_offset = int.from_bytes(bytearray(inferior.read_memory(instruction_ptr, 4)), "little")
            instruction_ptr += 4
            got_entry = instruction_ptr + relative_offset
            inferior.write(log_entry.patch_func_ptr.to_bytes(8, "little"))

        steal_refcount(master_lib, log_entry.target_func_ptr, data.path)
        log_entry.is_active = True
        write_log_entry(master_lib, log_entry, index)

Patch()
PatchLog()
ReapplyPatch()

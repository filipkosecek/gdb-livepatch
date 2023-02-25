import gdb
from datetime import datetime

MAGIC_CONSTANT = 153823877865751
HEADER_SIZE = 32
LOG_ENTRY_SIZE = 32
type_list = ["char", "uint64_t", "int32_t"]
LOG_SIZE = 2*4096
PATCH_BACKUP_SIZE = 4096

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
        header_addr = int(find_object_obj("patch_header", objfile_path).address)
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

    header_addr = int(find_object_obj("patch_header", objfile_path).address)

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
        patch_data_offset: int,
        path_len: int,
        membackup_len: int):
        self.target_func_ptr = target_func_ptr
        self.patch_func_ptr = patch_func_ptr
        if patch_type != "O" and patch_type != "L":
            raise gdb.GdbError("Got wrong patch type.")
        if patch_type == "O":
            self.patch_type = 0
        else:
            self.patch_type = 1
        self.timestamp = timestamp
        self.patch_data_offset = patch_data_offset
        self.path_len = path_len
        self.membackup_len = membackup_len

def read_log_entry(objfile_name: str, index: int) -> struct_log_entry:
    objfile = gdb.lookup_objfile(objfile_name)
    header = read_header(objfile_name)
    #TODO
    if header.magic != MAGIC_CONSTANT or header.contains_log == False:
        return None
    if index*LOG_ENTRY_SIZE >= LOG_SIZE:
        return None

    log_address = int(find_object_obj("patch_log", objfile_name).address)
    log_address += index*LOG_ENTRY_SIZE
    inferior = gdb.selected_inferior()
    buffer = bytearray(inferior.read_memory(log_address, LOG_ENTRY_SIZE))
    target_func_ptr = int.from_bytes(buffer[0:8], "little")
    patch_func_ptr = int.from_bytes(buffer[8:16], "little")
    patch_type = int.from_bytes(buffer[16:18], "little")
    if patch_type == 0:
        patch_type_str = "O"
    else:
        patch_type_str = "L"
    timestamp = int.from_bytes(buffer[18:22], "little")
    patch_data_offset = int.from_bytes(buffer[22:26], "little")
    path_len = int.from_bytes(buffer[26:28], "little")
    membackup_len = int.from_bytes(buffer[28:32], "little")
    return struct_log_entry(target_func_ptr, patch_func_ptr, patch_type_str, timestamp, patch_data_offset, path_len, membackup_len)

class struct_patch_backup:
    def __init__(self, path: str, membackup: bytearray):
        self.path = path
        self.membackup = membackup

def read_log_entry_data(objfile_path: str, index: int) -> struct_patch_backup:
    log_entry = read_log_entry(objfile_path, index)
    #no data
    if log_entry.path_len == 0 and log_entry.membackup_len == 0:
        return None
    log_data_ptr = int(find_object_obj("patch_backup", objfile_path).address)
    log_data_ptr += log_entry.patch_data_offset
    buffer = bytearray(gdb.selected_inferior().read_memory(log_data_ptr, log_entry.path_len + log_entry.membackup_len))
    return struct_patch_backup(buffer[0:log_entry.path_len].decode(), buffer[log_entry.path_len:(log_entry.path_len + log_entry.membackup_len)])

def add_log_entry(objfile_path: str, log_entry: struct_log_entry, patch_backup: struct_patch_backup) -> None:
    header = read_header(objfile_path)
    log_entry_ptr = int(find_object_obj("patch_log", objfile_path).address)
    patch_backup_ptr = int(find_object_obj("patch_backup", objfile_path).address)
    log_size = header.log_entries_count*LOG_ENTRY_SIZE
    backup_size = header.patch_data_array_len
    log_entry_ptr += log_size
    patch_backup_ptr += backup_size
    #TODO at least print an error message
    if log_size >= LOG_SIZE or backup_size >= PATCH_BACKUP_SIZE:
        return None
    header.log_entries_count += 1
    offset = header.patch_data_array_len
    if patch_backup is not None:
        header.patch_data_array_len += len(patch_backup.path) + len(patch_backup.membackup)
    header.print()
    write_header(objfile_path, header)
    if patch_backup is None:
        log_entry.path_len = 0
        log_entry.membackup_len = 0
        log_entry.patch_data_offset = 0
    else:
        log_entry.path_len = len(patch_backup.path)
        log_entry.membackup_len = len(patch_backup.membackup)
        log_entry.patch_data_offset = offset

    inferior = gdb.selected_inferior()
    log_entry_buf = bytearray()
    log_entry_buf.extend(log_entry.target_func_ptr.to_bytes(8, "little"))
    log_entry_buf.extend(log_entry.patch_func_ptr.to_bytes(8, "little"))
    if log_entry.patch_type == "O":
        tmp = 0
    elif log_entry.patch_type == "L":
        tmp = 1
    else:
        tmp = 1000

    log_entry_buf.extend(tmp.to_bytes(2, "little"))
    log_entry_buf.extend(log_entry.timestamp.to_bytes(4, "little"))
    log_entry_buf.extend(log_entry.patch_data_offset.to_bytes(4, "little"))
    log_entry_buf.extend(log_entry.path_len.to_bytes(2, "little"))
    log_entry_buf.extend(log_entry.membackup_len.to_bytes(4, "little"))
    inferior.write_memory(log_entry_ptr, log_entry_buf, len(log_entry_buf))

    if patch_backup is not None:
        backup_buf = bytearray(patch_backup.path.encode())
        backup_buf.extend(patch_backup.membackup)
        inferior.write_memory(patch_backup_ptr, backup_buf, len(backup_buf))

def find_master_lib() -> str:
    for objfile in gdb.objfiles():
        header = read_header(objfile.filename)
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

class PatchStrategy:
    def __init__(self, lib_handle: gdb.Value, dlclose: gdb.Value, path: str, target_func: str, patch_func: str):
        self.lib_handle = lib_handle
        self.dlclose = dlclose
        self.path = path
        self.target_func = target_func
        self.patch_func = patch_func

    def do_patch(self):
        pass
    
    def clean(self):
        pass

class PatchOwnStrategy (PatchStrategy):
    def __init__(self, lib_handle: gdb.Value, dlclose: gdb.Value, path: str,  target_func: str, patch_func: str):
        super().__init__(lib_handle, dlclose, path, target_func, patch_func)

    def do_patch(self):
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
            patch_addr = find_object_obj(self.patch_func, self.path).cast(gdb.lookup_type("uint64_t"))
        except:
            raise gdb.GdbError("Couldn't find " + self.patch_func  + " symbol.")
        patch_addr_arr = int(patch_addr).to_bytes(8, byteorder = "little")

        #write trampoline
        trampoline = AbsoluteTrampoline()

        #backup data
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

    def do_patch(self):
        #find target and patch functions
        try:
            target = "'" + self.target_func + "@plt'"
            target = find_object(target)
            patch = find_object_obj(self.patch_func, self.path)
            patch = patch.cast(gdb.lookup_type("char").pointer())
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
        patchlib = gdb.lookup_objfile(objfile)
        header = read_header(objfile)
        if header is None:
            #TODO
            raise gdb.GdbError("Couldn't find header.")
        commands_len = header.commands_len
        commands = int(patchlib.lookup_global_symbol("patch_commands").value().address)

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
        
    def clean(self, objfile: str) -> None:
        rn = find_patch_section_range(".patch.backup", objfile)
        base = rn[0]
        inferior = gdb.selected_inferior()
        lib_handle_arr = bytearray(inferior.read_memory(base, 8))
        lib_handle = int.from_bytes(lib_handle_arr, "little")
        base += len(lib_handle_arr)
        while True:
            index = 0
            target_func_addr = int.from_bytes(bytearray(inferior.read_memory(base + index, 8)), "little")
            index += 8
            padding_size = int.from_bytes(bytearray(inferior.read_memory(base + index, 1)), "little")
            if padding_size == 0:
                break
            index += padding_size
            memcontent = bytearray(inferior.read_memory(base + index, 24 - index))

            inferior.write_memory(target_func_addr, memcontent, len(memcontent))
            base += 24

        self.dlclose_addr(lib_handle)


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
        for patch in metadata:
            target_func = patch[1]
            patch_func = patch[2]

            if patch[0] == 'O':
                self.strategy = PatchOwnStrategy(self.dlopen_ret, self.dlclose_addr, argv[0], target_func, patch_func)
            elif patch[0] == 'L':
                self.strategy = PatchLibStrategy(self.dlopen_ret, self.dlclose_addr, argv[0], target_func, patch_func)
            else:
                raise gdb.GdbError("Patching own and library functions is only supported for now.")

            self.strategy.do_patch()

Patch()

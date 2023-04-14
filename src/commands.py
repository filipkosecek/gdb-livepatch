import gdb
import time
import re
from datetime import datetime

BYTE_ORDER = "little"

PAGE_SIZE = 4096
MAGIC_CONSTANT = 1024
HEADER_SIZE = 32
LOG_ENTRY_SIZE = 32
type_list = ["char", "uint64_t", "int32_t"]
LOG_SIZE = 2*4096
PATCH_BACKUP_SIZE = PAGE_SIZE

PATCH_HEADER_VAR_NAME = "patch_header"
PATCH_LOG_VAR_NAME = "patch_log"
PATCH_LOG_DATA_VAR_NAME = "patch_backup"
PATCH_COMMANDS_VAR_NAME = "patch_commands"

HEX_REGEX = "0x[1-9a-f][0-9a-f]*"
DECIMAL_REGEX = "[1-9][0-9]*"
MAPPINGS_LINE_REGEX = "^ *" + HEX_REGEX + " *" + HEX_REGEX + " *" + HEX_REGEX

TRAMPOLINE_BITMAP_SIZE = 32
TRAMPOLINE_ARRAY_SIZE = 254
ABSOLUTE_TRAMPOLINE_SIZE = 13
PADDED_TRAMPOLINE_SIZE = 16
SHORT_TRAMPOLINE_SIZE = 5

MAX_PAGE_DIST = pow(2, 25)

master_lib_path = ""

def is_attached() -> bool:
    inferior = gdb.selected_inferior()
    if inferior.was_attached:
        return True
    return False

def c_string(s: str) -> gdb.Value:
    tmp = s + '\0'
    buffer = bytearray(tmp.encode())
    return gdb.Value(buffer, gdb.lookup_type("char").array(len(buffer)-1))

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

def find_object_static(symbol_name: str, objfile_name: str) -> int:
    try:
        objfile = gdb.lookup_objfile(objfile_name)
        symbol = int(objfile.lookup_static_symbol(symbol_name).value().address)
    except:
        raise gdb.GdbError("Couldn't find " + symbol_name + "in object file " + objfile_name + ".")
    else:
        return symbol

def addr_to_symbol(address: int) -> str:
    cmd = gdb.execute("info symbol " + str(address), to_string=True)
    match = re.match("No symbol matches .*\.", cmd)
    if match:
        return None
    result = cmd.split(' ')[0]
    match = re.match(".+@plt", result)
    if match:
        result = result.split('@')[0]
    return result

class struct_header:
    def __init__(self, magic: int, libhandle: int, trampoline_page_ptr: int, refcount: int, contains_log: bool, log_entries_count: int, patch_data_array_len: int, commands_len: int):
        self.magic = magic
        self.libhandle = libhandle
        self.trampoline_page_ptr = trampoline_page_ptr
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
        print(self.trampoline_page_ptr)
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
        header_addr = find_object_static(PATCH_HEADER_VAR_NAME, objfile_path)
    except:
        return None
    buffer = inferior.read_memory(header_addr, HEADER_SIZE)
    magic = int.from_bytes(buffer[:4], "little")
    if magic != MAGIC_CONSTANT:
        return None
    libhandle = int.from_bytes(buffer[4:12], "little")
    trampoline_page_ptr = int.from_bytes(buffer[12:20], "little")
    refcount = int.from_bytes(buffer[20:22], "little")
    contains_log = int.from_bytes(buffer[22:24], "little")
    if contains_log == 0:
        contains_log_bool = False
    elif contains_log == 1:
        contains_log_bool = True
    else:
        raise gdb.GdbError("Got wrong value for contains_log value.")
    log_entries_count = int.from_bytes(buffer[24:26], "little")
    patch_data_array_len = int.from_bytes(buffer[26:28], "little")
    commands_len = int.from_bytes(buffer[28:32], "little")
    return struct_header(magic, libhandle, trampoline_page_ptr, refcount, contains_log, log_entries_count, patch_data_array_len, commands_len)

def write_header(objfile_path: str, header: struct_header) -> None:
    if header.magic != MAGIC_CONSTANT:
        raise gdb.GdbError("Got wrong value of magic constant while trying to write header.")

    header_addr = find_object_static(PATCH_HEADER_VAR_NAME, objfile_path)

    buffer = bytearray()
    buffer.extend(header.magic.to_bytes(4, "little"))
    buffer.extend(header.libhandle.to_bytes(8, "little"))
    buffer.extend(header.trampoline_page_ptr.to_bytes(8, "little"))
    buffer.extend(header.refcount.to_bytes(2, "little"))
    if header.contains_log:
        tmp = 1
    else:
        tmp = 0
    buffer.extend(tmp.to_bytes(2, "little"))
    buffer.extend(header.log_entries_count.to_bytes(2, "little"))
    buffer.extend(header.patch_data_array_len.to_bytes(2, "little"))
    buffer.extend(header.commands_len.to_bytes(4, "little"))

    inferior = gdb.selected_inferior()
    inferior.write_memory(header_addr, buffer, len(buffer))

def find_mappings() -> tuple[set[int], dict[int, int]]:
    mappings = gdb.execute("info proc mappings", to_string=True)
    mappings_list = re.findall(MAPPINGS_LINE_REGEX, mappings, re.MULTILINE)
    allocated_pages = set()
    allocated_pages_sizes = dict()
    for line in mappings_list:
        tmp = line.split()
        page = int(tmp[0], 16)
        size = int(tmp[2], 16)
        allocated_pages.add(page)
        allocated_pages_sizes[page] = size
    return allocated_pages, allocated_pages_sizes

def find_nearest_free_page(address: int) -> int:
    current = address & 0xfffffffffffff000
    ret = find_mappings()
    allocated_pages = ret[0]
    allocated_pages_sizes = ret[1]
    left = current
    right = current
    while left > 0 or right < 0x7fffffffffff:
        if left > 0:
            if abs(left - current) <= MAX_PAGE_DIST and left not in allocated_pages:
                return left
            left -= allocated_pages_sizes[left]

        if right < 0x7fffffffffff:
            if abs(right - current) <= MAX_PAGE_DIST and right not in allocated_pages:
                return right
            right += allocated_pages_sizes[right]

    return 0

def init_trampoline_bitmap(address: int):
    inferior = gdb.selected_inferior()
    inferior.write_memory(address, bytearray(TRAMPOLINE_BITMAP_SIZE), TRAMPOLINE_BITMAP_SIZE)

def save_registers() -> dict[str, int]:
    result = dict()
    result["rip"] = int(gdb.parse_and_eval("$rip").cast(gdb.lookup_type("uint64_t")))
    result["rax"] = int(gdb.parse_and_eval("$rax").cast(gdb.lookup_type("uint64_t")))
    result["rbx"] = int(gdb.parse_and_eval("$rbx").cast(gdb.lookup_type("uint64_t")))
    result["rcx"] = int(gdb.parse_and_eval("$rcx").cast(gdb.lookup_type("uint64_t")))
    result["rdx"] = int(gdb.parse_and_eval("$rdx").cast(gdb.lookup_type("uint64_t")))
    result["rsi"] = int(gdb.parse_and_eval("$rsi").cast(gdb.lookup_type("uint64_t")))
    result["rdi"] = int(gdb.parse_and_eval("$rdi").cast(gdb.lookup_type("uint64_t")))
    result["rbp"] = int(gdb.parse_and_eval("$rbp").cast(gdb.lookup_type("uint64_t")))
    result["rsp"] = int(gdb.parse_and_eval("$rsp").cast(gdb.lookup_type("uint64_t")))
    result["r8"] = int(gdb.parse_and_eval("$r8").cast(gdb.lookup_type("uint64_t")))
    result["r9"] = int(gdb.parse_and_eval("$r9").cast(gdb.lookup_type("uint64_t")))
    result["r10"] = int(gdb.parse_and_eval("$r10").cast(gdb.lookup_type("uint64_t")))
    result["r11"] = int(gdb.parse_and_eval("$r11").cast(gdb.lookup_type("uint64_t")))
    result["r12"] = int(gdb.parse_and_eval("$r12").cast(gdb.lookup_type("uint64_t")))
    result["r13"] = int(gdb.parse_and_eval("$r13").cast(gdb.lookup_type("uint64_t")))
    result["r14"] = int(gdb.parse_and_eval("$r14").cast(gdb.lookup_type("uint64_t")))
    result["r15"] = int(gdb.parse_and_eval("$r15").cast(gdb.lookup_type("uint64_t")))
    return result

def restore_registers(registers: dict[str, int]):
    for reg in registers:
        gdb.execute("set $" + reg + "=" + str(registers[reg]))

def exec_mmap(address: int, prot: int, flags: int) -> int:
    inferior = gdb.selected_inferior()
    registers = save_registers()
    rip = registers["rip"]
    syscall_instruction = bytearray.fromhex("0f 05")
    membackup = bytearray(inferior.read_memory(rip, 2))
    inferior.write_memory(rip, syscall_instruction, 2)
    #set register values
    gdb.execute("set $rax = 9")
    gdb.execute("set $rdi = " + str(address))
    gdb.execute("set $rsi = " + str(PAGE_SIZE))
    gdb.execute("set $rdx = " + str(prot))
    gdb.execute("set $r10 = " + str(flags))
    gdb.execute("set $r8 = " + str(-1))
    gdb.execute("set $r9 = " + str(0))
    gdb.execute("si")
    ret = int(gdb.parse_and_eval("$rax").cast(gdb.lookup_type("uint64_t")))
    restore_registers(registers)
    inferior.write_memory(rip, membackup, 2)
    return ret

def exec_munmap(address: int) -> int:
    inferior = gdb.selected_inferior()
    registers = save_registers()
    rip = registers["rip"]
    syscall_instruction = bytearray.fromhex("0f 05")
    membackup = bytearray(inferior.read_memory(rip, 2))
    inferior.write_memory(rip, syscall_instruction, 2)
    #set register values
    gdb.execute("set $rax = 11")
    gdb.execute("set $rdi = " + str(address))
    gdb.execute("set $rsi = " + str(PAGE_SIZE))
    gdb.execute("si")
    ret = int(gdb.parse_and_eval("$rax").cast(gdb.lookup_type("uint64_t")))
    restore_registers(registers)
    inferior.write_memory(rip, membackup, 2)
    return ret

def alloc_trampoline_page(address: int) -> int:
    ptr = exec_mmap(address, 7, 34)
    if ptr == -1:
        return 0
    init_trampoline_bitmap(ptr)
    return ptr

def free_trampoline_page(address: int):
    hdr = read_header(master_lib_path)
    hdr.trampoline_page_ptr = 0
    write_header(master_lib_path, hdr)
    if exec_munmap(address) == -1:
        raise gdb.GdbError("Couldn't unmap the page.")

def get_trampoline_count(bitmap_address: int) -> int:
    inferior = gdb.selected_inferior()
    buffer = bytearray(inferior.read_memory(bitmap_address, TRAMPOLINE_BITMAP_SIZE))
    counter = 0
    for word_index in range(TRAMPOLINE_BITMAP_SIZE):
        for bit in range(8):
            if (buffer[word_index] & (1 << bit)) != 0:
                counter += 1
    return counter

def find_first_free_trampoline_index(bitmap_address: int) -> int:
    inferior = gdb.selected_inferior()
    buffer = bytearray(inferior.read_memory(bitmap_address, TRAMPOLINE_BITMAP_SIZE))
    for word_index in range(TRAMPOLINE_ARRAY_SIZE):
        word = buffer[word_index]
        for bit in range(8):
            if (word & (1 << bit)) == 0:
                #set bit
                buffer[word_index] |= (1 << bit)
                inferior.write_memory(bitmap_address, buffer, len(buffer))
                return word_index*8 + bit
    return -1

def alloc_trampoline(target_function_address: int) -> int:
    hdr = read_header(master_lib_path)
    if hdr.trampoline_page_ptr == 0:
        page_base = find_nearest_free_page(target_function_address)
        if page_base == 0:
            return 0
        alloc_trampoline_page(page_base)
        hdr.trampoline_page_ptr = page_base
        write_header(master_lib_path, hdr)
    index = find_first_free_trampoline_index(hdr.trampoline_page_ptr)
    if index == -1:
        return 0
    return hdr.trampoline_page_ptr + TRAMPOLINE_BITMAP_SIZE + index*PADDED_TRAMPOLINE_SIZE

def free_trampoline(trampoline_address: int):
    hdr = read_header(master_lib_path)
    if hdr.trampoline_page_ptr == 0:
        return
    index = int((trampoline_address - hdr.trampoline_page_ptr - TRAMPOLINE_BITMAP_SIZE) / 16)
    word_index = int(index / 8)
    bit_index = index % 8
    inferior = gdb.selected_inferior()
    buffer = bytearray(inferior.read_memory(hdr.trampoline_page_ptr, TRAMPOLINE_BITMAP_SIZE))
    #reset bit
    buffer[word_index] &= (~(1 << bit_index))
    inferior.write_memory(hdr.trampoline_page_ptr, buffer, len(buffer))

def free_trampoline_from_instruction(instruction_ptr: int):
    inferior = gdb.selected_inferior()
    instruction_ptr += 1
    relative_offset = int.from_bytes(bytearray(inferior.read_memory(instruction_ptr, SHORT_TRAMPOLINE_SIZE - 1)), "little", signed=True)
    free_trampoline(instruction_ptr + SHORT_TRAMPOLINE_SIZE + relative_offset)

def find_object_dlsym(symbol_name: str, objfile_name: str) -> int:
    dlsym = find_object("dlsym")
    hdr = read_header(objfile_name)
    if hdr is None:
        return 0
    libhandle = hdr.libhandle
    symbol_address = int(dlsym(libhandle, c_string(symbol_name)).cast(gdb.lookup_type("uint64_t")))
    if symbol_address == 0:
        raise gdb.GdbError("Couldn't find symbol " + symbol_name)
    return symbol_address

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

    def to_string(self):
        global master_lib_path
        master_lib = gdb.lookup_objfile(master_lib_path)
        backup_ptr = find_object_dlsym(PATCH_LOG_DATA_VAR_NAME, master_lib_path)
        backup_ptr += self.path_offset
        path = bytearray(gdb.selected_inferior().read_memory(backup_ptr, self.path_len)).decode("ascii")

        target_func_str = addr_to_symbol(self.target_func_ptr)
        patch_func_str = addr_to_symbol(self.patch_func_ptr)

        if target_func_str is None:
            target_func_str = hex(self.target_func_ptr)
        if patch_func_str is None:
            patch_func_str = hex(self.patch_func_ptr)

        tmp = " "
        if self.is_active:
            tmp = "* "

        try:
            gdb.lookup_objfile(path)
        except:
            return "".join([tmp, str(datetime.fromtimestamp(self.timestamp)), ": ", target_func_str, " -> ", path, ":", "unknown function (library is closed)"])
        return "".join([tmp, str(datetime.fromtimestamp(self.timestamp)), ": ", target_func_str, " -> ", path, ":", patch_func_str])

def bytearray_to_log_entry(buffer: bytearray) -> struct_log_entry:
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

def read_log_entry(index: int) -> struct_log_entry:
    global master_lib_path
    objfile = gdb.lookup_objfile(master_lib_path)
    if objfile is None:
        return None
    header = read_header(master_lib_path)
    #TODO
    if header.magic != MAGIC_CONSTANT or header.contains_log == False:
        return None
    if index*LOG_ENTRY_SIZE >= LOG_SIZE:
        return None

    log_address = find_object_dlsym(PATCH_LOG_VAR_NAME, master_lib_path)
    log_address += index*LOG_ENTRY_SIZE
    inferior = gdb.selected_inferior()
    buffer = bytearray(inferior.read_memory(log_address, LOG_ENTRY_SIZE))
    return bytearray_to_log_entry(buffer)

def log_entry_to_bytearray(log_entry: struct_log_entry) -> bytearray:
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
    return log_entry_buf

def write_log_entry(log_entry: struct_log_entry, index: int) -> None:
    global master_lib_path
    log_ptr = find_object_dlsym(PATCH_LOG_VAR_NAME, master_lib_path)
    log_ptr += index*LOG_ENTRY_SIZE

    log_entry_buf = log_entry_to_bytearray(log_entry)
    gdb.selected_inferior().write_memory(log_ptr, log_entry_buf, len(log_entry_buf))

def get_last_log_entry() -> struct_log_entry:
    global master_lib_path
    hdr = read_header(master_lib_path)
    return read_log_entry(hdr.log_entries_count - 1)

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

def read_log_entry_data(log_entry: struct_log_entry) -> struct_patch_backup:
    global master_lib_path
    path = None
    membackup = None
    log_data_ptr = find_object_dlsym(PATCH_LOG_DATA_VAR_NAME, master_lib_path)
    if log_entry.path_len != 0:
        path = bytearray(gdb.selected_inferior().read_memory(log_data_ptr + log_entry.path_offset, log_entry.path_len)).decode("ascii")
    if log_entry.membackup_len != 0:
        membackup = bytearray(gdb.selected_inferior().read_memory(log_data_ptr + log_entry.membackup_offset, log_entry.membackup_len))
    return struct_patch_backup(path, membackup)

def add_log_entry(log_entry: struct_log_entry, patch_backup: struct_patch_backup) -> None:
    global master_lib_path
    header = read_header(master_lib_path)
    index = header.log_entries_count
    patch_backup_ptr = find_object_dlsym(PATCH_LOG_DATA_VAR_NAME, master_lib_path)
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
    write_header(master_lib_path, header)

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

    write_log_entry(log_entry, index)

#TODO also sets log is_active flag
def find_last_patch_and_set_as_inactive(func_address: int) -> str:
    global master_lib_path
    hdr = read_header(master_lib_path)
    i = hdr.log_entries_count - 1
    log_ptr = find_object_dlsym(PATCH_LOG_VAR_NAME, master_lib_path)
    buffer = bytearray(gdb.selected_inferior().read_memory(log_ptr, hdr.log_entries_count*LOG_ENTRY_SIZE))
    result = None
    while i >= 0:
        entry = bytearray_to_log_entry(buffer[(i*LOG_ENTRY_SIZE):((i+1)*LOG_ENTRY_SIZE)])
        if entry.is_active and entry.target_func_ptr == func_address:
            result = read_log_entry_data(entry).path
            instruction_prefix = bytearray(gdb.selected_inferior().read_memory(entry.target_func_ptr, 1))
            if instruction_prefix[0] == 0xe9:
                free_trampoline_from_instruction(entry.target_func_ptr)
            entry.is_active = False
            write_log_entry(entry, i)
            break
        i -= 1
    return result

def find_first_patch(func_address: int) -> struct_log_entry:
    global master_lib_path
    hdr = read_header(master_lib_path)
    log_ptr = find_object_dlsym(PATCH_LOG_VAR_NAME, master_lib_path)
    buffer = bytearray(gdb.selected_inferior().read_memory(log_ptr, hdr.log_entries_count*LOG_ENTRY_SIZE))
    for i in range(hdr.log_entries_count):
        entry = bytearray_to_log_entry(buffer[(i*LOG_ENTRY_SIZE):((i+1)*LOG_ENTRY_SIZE)])
        if entry.target_func_ptr == func_address:
            return entry
    return None

def copy_log(dest: str, src: str):
    global master_lib_path
    src_log = find_object_dlsym(PATCH_LOG_VAR_NAME, src)
    src_backup = find_object_dlsym(PATCH_LOG_DATA_VAR_NAME, src)
    dest_log = find_object_dlsym(PATCH_LOG_VAR_NAME, dest)
    dest_backup = find_object_dlsym(PATCH_LOG_DATA_VAR_NAME, dest)
    src_hdr = read_header(src)
    src_hdr.contains_log = False
    write_header(src, src_hdr)
    dest_hdr = read_header(dest)
    dest_hdr.contains_log = True
    dest_hdr.log_entries_count = src_hdr.log_entries_count
    dest_hdr.patch_data_array_len = src_hdr.patch_data_array_len
    dest_hdr.trampoline_page_ptr = src_hdr.trampoline_page_ptr
    write_header(dest, dest_hdr)
    inferior = gdb.selected_inferior()
    log_buffer = bytearray(inferior.read_memory(src_log, src_hdr.log_entries_count*LOG_ENTRY_SIZE))
    backup_buffer = bytearray(inferior.read_memory(src_backup, src_hdr.patch_data_array_len))
    inferior.write_memory(dest_log, log_buffer, len(log_buffer))
    inferior.write_memory(dest_backup, backup_buffer, len(backup_buffer))
    master_lib_path = dest

def close_lib(lib: str):
    global master_lib_path
    hdr = read_header(lib)
    is_last = False
    if hdr.contains_log:
        hdr.contains_log = False
        is_last = True
        write_header(lib, hdr)
        for objfile in gdb.objfiles():
            try:
                header = read_header(objfile.filename)
            except:
                continue
            if header is None:
                continue
            if header.magic == MAGIC_CONSTANT and objfile.filename != lib:
                copy_log(objfile.filename, lib)
                is_last = False
    if is_last:
        if hdr.trampoline_page_ptr != 0:
            free_trampoline_page(hdr.trampoline_page_ptr)
        master_lib_path = ""
    dlclose = find_object("dlclose")
    dlclose(hdr.libhandle)

def decrease_refcount(lib: str):
    hdr = read_header(lib)
    hdr.refcount -= 1
    write_header(lib, hdr)
    if hdr.refcount <= 0:
        close_lib(lib)

def steal_refcount(func_address: int, current_lib: str):
    lib = find_last_patch_and_set_as_inactive(func_address)
    if lib is not None:
        pass
        #TODO use decrease_refcount instead
        decrease_refcount(lib)

    current = read_header(current_lib)
    current.refcount += 1
    write_header(current_lib, current)

def find_master_lib() -> None:
    global master_lib_path
    master_lib_path = ""
    for objfile in gdb.objfiles():
        try:
            header = read_header(objfile.filename)
        except:
            continue
        if header is None:
            continue
        if header.contains_log:
            master_lib_path = objfile.filename

class AbsoluteTrampoline:
    def __init__(self):
       self.trampoline = bytearray.fromhex("49 bb 00 00 00 00 00 00 00 00 41 ff e3")

    def size(self) -> int:
        return len(self.trampoline)

    def complete_address(self, addr: bytearray):
        for i in range(8):
            self.trampoline[i+2] = addr[i]

    def write_trampoline(self, address: int):
        inferior = gdb.selected_inferior()
        inferior.write_memory(address, self.trampoline, len(self.trampoline))

class AlignedAbsoluteTrampoline(AbsoluteTrampoline):
    def __init__(self):
        self.trampoline = bytearray.fromhex("49 bb 00 00 00 00 00 00 00 00 41 ff e3 90 90 90")

class RelativeTrampoline:
    def __init__(self):
        self.trampoline = bytearray.fromhex("e9 00 00 00 00")

    def size(self) -> int:
        return len(self.trampoline)

    def complete_address(self, address: int):
        offset = address.to_bytes(4, "little", signed=True)
        for i in range(4):
            self.trampoline[i+1] = offset[i]

    def write_trampoline(self, address: int):
        inferior = gdb.selected_inferior()
        inferior.write_memory(address, self.trampoline, len(self.trampoline))

class PatchStrategy:
    def __init__(self, lib_handle: gdb.Value, dlclose: gdb.Value, path: str, target_func: str, patch_func: str):
        self.lib_handle = lib_handle
        self.dlclose = dlclose
        self.path = path
        self.target_func = target_func
        self.patch_func = patch_func

    def do_patch(self, path_offset: int, path_len: int, membackup_offset: int, membackup_len: int):
        pass
    
    def clean(self):
        pass

class PatchOwnStrategy (PatchStrategy):
    def __init__(self, lib_handle: gdb.Value, dlclose: gdb.Value, path: str,  target_func: str, patch_func: str):
        super().__init__(lib_handle, dlclose, path, target_func, patch_func)

    def do_patch(self, path_offset: int, path_len: int, membackup_offset: int, membackup_len: int):
        match = re.match(HEX_REGEX, self.target_func)
        if match:
            target_addr = int(self.target_func, 16)
        else:
            try:
                target_addr = find_object(self.target_func)
                target_addr = int(target_addr.cast(gdb.lookup_type("uint64_t")))
            except:
                #TODO
                self.clean()
                raise gdb.GdbError("Couldn't find target function symbol.")

        #control flow must not be where the trampoline is about to be inserted
        #TODO control flow must not be in the function, it may lead to crash
        rip = int(gdb.parse_and_eval("$rip").cast(gdb.lookup_type("uint64_t")))
        if rip >= target_addr and rip < target_addr + 13:
            self.clean()
            raise gdb.GdbError("The code segment where the trampoline is about to be inserted is being executed.")

        #try to resolve symbol for patch function
        try:
            patch_addr = find_object_dlsym(self.patch_func, self.path)
        except:
            raise gdb.GdbError("Couldn't find " + self.patch_func  + " symbol.")
        patch_addr_arr = patch_addr.to_bytes(8, byteorder = "little")

        #steal refcount
        steal_refcount(target_addr, self.path)

        #write to log
        entry = struct_log_entry(target_addr, patch_addr, "O", int(time.time()), 0, True, 0, 0, 0)
        backup = struct_patch_backup(None, None)
        if path_offset != -1:
            entry.path_offset = path_offset
            entry.path_len = path_len
        else:
            backup.path = self.path
            entry.path_len = len(self.path)

        tmp = find_first_patch(target_addr)
        if tmp is None:
            backup.membackup = bytearray(gdb.selected_inferior().read_memory(target_addr, ABSOLUTE_TRAMPOLINE_SIZE))
            entry.membackup_len = len(backup.membackup)
        else:
            entry.membackup_offset = tmp.membackup_offset
            entry.membackup_len = tmp.membackup_len

        #write trampoline
        ret = alloc_trampoline(target_addr)
        inferior = gdb.selected_inferior()
        if ret == 0:
            trampoline = AbsoluteTrampoline()
            trampoline.complete_address(patch_addr_arr)
            trampoline.write_trampoline(target_addr)
        else:
            short_trampoline = RelativeTrampoline()
            long_trampoline = AbsoluteTrampoline()
            long_trampoline.complete_address(patch_addr.to_bytes(8, BYTE_ORDER))
            relative_offset = ret - target_addr - SHORT_TRAMPOLINE_SIZE
            short_trampoline.complete_address(relative_offset)
            long_trampoline.write_trampoline(ret)
            short_trampoline.write_trampoline(target_addr)

        #write changes to the log
        add_log_entry(entry, backup)

    def clean(self):
        self.dlclose(self.lib_handle)

class PatchLibStrategy (PatchStrategy):
    def __init__(self, lib_handle: gdb.Value, dlclose: gdb.Value, path: str, target_func: str, patch_func: str):
        super().__init__(lib_handle, dlclose, path, target_func, patch_func)

    def do_patch(self, path_offset: int, path_len: int, membackup_offset: int, membackup_len: int):
        inferior = gdb.selected_inferior()
        #find target and patch functions
        try:
            target = "'" + self.target_func + "@plt'"
            target = find_object(target)
            target_ptr = int(target.cast(gdb.lookup_type("uint64_t")))
            patch = find_object_dlsym(self.patch_func, self.path)
        except:
            self.dlclose(self.lib_handle)

        #fetch relative offset
        relative_addr = int.from_bytes(inferior.read_memory(target_ptr + 2, 4), BYTE_ORDER, signed=True)

        #fetch next instruction's address
        next_instruction = target_ptr + 6

        #calculate got.plt entry
        addr_got = next_instruction + relative_addr
        patch_arr = patch.to_bytes(8, byteorder = "little")

        #steal refcount
        steal_refcount(target_ptr, self.path)

        #write to log
        entry = struct_log_entry(target_ptr, patch, "L", int(time.time()), 0, True, 0, 0, 0)
        backup = struct_patch_backup(None, None)
        if path_offset != -1:
            entry.path_offset = path_offset
            entry.path_len = path_len
        else:
            backup.path = self.path
            entry.path_len = len(self.path)

        tmp = find_first_patch(target_ptr)
        if tmp is None:
            backup.membackup = bytearray(inferior.read_memory(addr_got, 8))
            entry.membackup_len = len(backup.membackup)
        else:
            entry.membackup_offset = tmp.membackup_offset
            entry.membackup_len = tmp.membackup_len
        add_log_entry(entry, backup)

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
        header = read_header(objfile)
        if header is None:
            #TODO
            raise gdb.GdbError("Couldn't find header.")
        commands_len = header.commands_len
        commands = find_object_dlsym(PATCH_COMMANDS_VAR_NAME, objfile)

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
        self.dlopen_ret = self.dlopen_addr(c_string(path), 2)
        if self.dlopen_ret == 0:
            raise gdb.GdbError("Couldn't open the patch library.")
        header = read_header(path)
        if header is None or header.magic != MAGIC_CONSTANT:
            raise gdb.GdbError("Object file " + path + " has a wrong format.")
        header.libhandle = int(self.dlopen_ret.cast(gdb.lookup_type("uint64_t")))
        write_header(path, header)
        
    def complete(self, text, word):
        return gdb.COMPLETE_FILENAME

    def invoke(self, arg, from_tty):
        global master_lib_path
        self.type_dict.clear()
        argv = gdb.string_to_argv(arg)
        if len(argv) != 1:
            raise gdb.GdbError("patch takes one parameter")

        if not is_attached():
            raise gdb.GdbError("No process attached.")

        #find necessary objects
        self.dlopen_addr = find_object("dlopen")
        self.dlclose_addr = find_object("dlclose")
        self.is_patchable()
        find_master_lib()

        self.load_patch_lib(argv[0])
        metadata = self.extract_patch_metadata(argv[0])
        if not master_lib_path:
            master_lib_path = argv[0]
        tmp = read_header(master_lib_path)
        tmp.contains_log = True
        write_header(master_lib_path, tmp)
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
                self.strategy.do_patch(-1, 0, -1, 0)
                first_entry = get_last_log_entry()
            else:
                self.strategy.do_patch(first_entry.path_offset, first_entry.path_len, -1, 0)
            counter += 1

class PatchLog(gdb.Command):
    def __init__(self):
        super(PatchLog, self).__init__("patch-log", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        global master_lib_path
        argv = gdb.string_to_argv(arg)
        if len(argv) != 0:
            raise gdb.GdbError("patch-log takes no parameters")

        if not is_attached():
            raise gdb.GdbError("No process attached.")

        print("[0] revert")

        find_master_lib()
        if not master_lib_path:
            print("Cannot find the log. No patch applied.")
            return
        header = read_header(master_lib_path)
        log_ptr = find_object_dlsym(PATCH_LOG_VAR_NAME, master_lib_path)
        buffer = bytearray(gdb.selected_inferior().read_memory(log_ptr, header.log_entries_count*LOG_ENTRY_SIZE))
        for i in range(header.log_entries_count):
            entry = bytearray_to_log_entry(buffer[(i*LOG_ENTRY_SIZE):((i+1)*LOG_ENTRY_SIZE)])
            print("[" + str(i+1) + "]" + entry.to_string())

#WARNING!!! sets found library as inactive
#TODO poor design
def find_active_entry_and_set_as_inactive(func_address: int) -> struct_log_entry:
    global master_lib_path
    size = read_header(master_lib_path).log_entries_count
    log_ptr = find_object_dlsym(PATCH_LOG_VAR_NAME, master_lib_path)
    buffer = bytearray(gdb.selected_inferior().read_memory(log_ptr, size*LOG_ENTRY_SIZE))
    result = None
    for i in range(size):
        entry = bytearray_to_log_entry(buffer[(i*LOG_ENTRY_SIZE):((i+1)*LOG_ENTRY_SIZE)])
        if entry.target_func_ptr == func_address and entry.is_active:
            instruction_prefix = bytearray(gdb.selected_inferior().read_memory(entry.target_func_ptr, 1))
            if instruction_prefix[0] == 0xe9:
                free_trampoline_from_instruction(entry.target_func_ptr)
            entry.is_active = False
            write_log_entry(entry, i)
            return entry
    return None

class ReapplyPatch(gdb.Command):
    def __init__(self):
        super(ReapplyPatch, self).__init__("patch-reapply", gdb.COMMAND_USER)

    def revert_all(self):
        header = read_header(master_lib_path)
        patch_log = find_object_dlsym(PATCH_LOG_VAR_NAME, master_lib_path)
        inferior = gdb.selected_inferior()
        buffer = bytearray(gdb.selected_inferior().read_memory(patch_log, header.log_entries_count*LOG_ENTRY_SIZE))
        for i in range(header.log_entries_count):
            entry = bytearray_to_log_entry(buffer[(i*LOG_ENTRY_SIZE):((i+1)*LOG_ENTRY_SIZE)])
            if not entry.is_active:
                continue
            backup = read_log_entry_data(entry)
            if backup.path is None or backup.membackup is None:
                raise gdb.GdbError("Cannot find memory backup or path.")
            if entry.patch_type == "O":
                instruction_prefix = bytearray(inferior.read_memory(entry.target_func_ptr, 1))
                if instruction_prefix[0] == 0xe9:
                    free_trampoline_from_instruction(entry.target_func_ptr)

                inferior.write_memory(entry.target_func_ptr, backup.membackup, len(backup.membackup))
            elif entry.patch_type == "L":
                instruction = entry.target_func_ptr + 2
                relative_offset = int.from_bytes(inferior.read_memory(instruction, 4), "little", signed=True)
                got_entry = entry.target_func_ptr + 6 + relative_offset
                inferior.write_memory(got_entry, backup.membackup, len(backup.membackup))

            decrease_refcount(backup.path)

    def revert(self, argv: list[str]):
        if len(argv) == 1:
            self.revert_all()
            return
        i = 1
        while i < len(argv):
            if re.match(HEX_REGEX, argv[i]):
                function_address = int(argv[i], 16)
            elif re.match(DECIMAL_REGEX, argv[i]):
                function_address = int(argv[i], 10)
            else:
                function_address = int(find_object(argv[i]).cast(gdb.lookup_type("uint64_t")))
            entry = find_active_entry_and_set_as_inactive(function_address)
            if entry is None:
                #try to find library function
                try:
                    function_address = int(find_object("'" + argv[i] + "@plt'").cast(gdb.lookup_type("uint64_t")))
                except:
                    raise gdb.GdbError("Nothing to revert.")
                entry = find_active_entry_and_set_as_inactive(function_address)
                if entry is None:
                    raise gdb.GdbError("Nothing to revert.")
            backup = read_log_entry_data(entry)
            path = backup.path
            membackup = backup.membackup
            inferior = gdb.selected_inferior()
            if path is None or membackup is None:
                raise gdb.GdbError("Fatal error, couldn't find membackup.")
            if entry.patch_type == "O":
                instruction_prefix = bytearray(inferior.read_memory(entry.target_func_ptr, 1))
                if instruction_prefix[0] == 0xe9:
                    free_trampoline_from_instruction(entry.target_func_ptr)
                inferior.write_memory(function_address, membackup, len(membackup))
            elif entry.patch_type == "L":
                instruction = function_address + 2
                relative_offset = int.from_bytes(bytearray(inferior.read_memory(instruction, 4)), "little", signed=True)
                got_entry = function_address + 6 + relative_offset
                inferior.write_memory(got_entry, membackup, len(membackup))

            decrease_refcount(backup.path)
            i += 1

    def invoke(self, arg, from_tty):
        global master_lib_path
        argv = gdb.string_to_argv(arg)
        if len(arg) < 1:
           raise gdb.GdbError("patch-reapply takes one parameter")
        if not is_attached():
            raise gdb.GdbError("No process attached.")
        find_master_lib()
        if not master_lib_path:
            raise gdb.GdbError("Couldn't find the log, master library is not present.")

        index = int(argv[0])
        if index == 0:
            self.revert(argv)
            return

        index -= 1

        log_entry = read_log_entry(index)
        if log_entry is None:
            raise gdb.GdbError("The log entry does not exist.")

        #nothing to do
        if log_entry.is_active:
            raise gdb.GdbError("The patch is active. No work to do.")

        #check if the library is still open
        data = read_log_entry_data(log_entry)
        if data.path is None:
            gdb.GdbError("Failed to fetch patchlib path.")
        try:
            gdb.lookup_objfile(data.path)
        except:
            #the lib is unmapped
            raise gdb.GdbError("The library has been closed. Cannot apply the patch. To apply the patch, use patch command.")
        if log_entry.patch_type == "O":
            if log_entry.membackup_len == ABSOLUTE_TRAMPOLINE_SIZE:
                trampoline = AbsoluteTrampoline()
                trampoline.complete_address(bytearray(log_entry.patch_func_ptr.to_bytes(8, "little")))
                trampoline.write_trampoline(log_entry.target_func_ptr)
            else:
                long_trampoline = AlignedAbsoluteTrampoline()
                short_trampoline = RelativeTrampoline()
                long_trampoline.complete_address(log_entry.patch_func_ptr.to_bytes(8, BYTE_ORDER))
                ret = alloc_trampoline(log_entry.target_func_ptr)
                if ret == 0:
                    raise gdb.GdbError("Cannot allocate a trampoline.")
                long_trampoline.write_trampoline(ret)
                relative_offset = ret - log_entry.target_func_ptr - SHORT_TRAMPOLINE_SIZE
                short_trampoline.complete_address(relative_offset)
                short_trampoline.write_trampoline(log_entry.target_func_ptr)

        elif log_entry.patch_type == "L":
            instruction_ptr = log_entry.target_func_ptr + 2
            inferior = gdb.selected_inferior()
            relative_offset = int.from_bytes(bytearray(inferior.read_memory(instruction_ptr, 4)), "little", signed=True)
            instruction_ptr += 4
            got_entry = instruction_ptr + relative_offset
            inferior.write(log_entry.patch_func_ptr.to_bytes(8, "little"))

        steal_refcount(log_entry.target_func_ptr, data.path)
        log_entry.is_active = True
        write_log_entry(log_entry, index)

Patch()
PatchLog()
ReapplyPatch()

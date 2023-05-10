import gdb
import time
import re
from datetime import datetime
from enum import Enum

type_list = ["uint64_t"]

# x86_64 architecture specifics
PAGE_SIZE = 4096
PAGE_MASK = 0xfffffffffffff000
BYTE_ORDER = "little"
NULL = 0

# metadata structures sizes and corresponding symbol names
MAGIC_CONSTANT = 1024
HEADER_SIZE = 48
LOG_ENTRY_SIZE = 32
LOG_SIZE = 2*4096
PATCH_BACKUP_SIZE = PAGE_SIZE
PATCH_HEADER_VAR_NAME = "patch_header"
PATCH_COMMANDS_VAR_NAME = "patch_commands"

# syscall numbers
SYS_MMAP = 9
SYS_MPROTECT = 10
SYS_MUNMAP = 11
# mman prot
PROT_READ = 1
PROT_WRITE = 2
PROT_EXEC = 4
# mman flags
MAP_PRIVATE = 2
MAP_ANONYMOUS = 32

# regexes
HEX_REGEX = "0x[1-9a-f][0-9a-f]*"
DECIMAL_REGEX = "[1-9][0-9]*"
MAPPINGS_LINE_REGEX = "^ *" + HEX_REGEX + " *" + HEX_REGEX + " *" + HEX_REGEX

# trampolines
TRAMPOLINE_BITMAP_SIZE = 32
TRAMPOLINE_ARRAY_SIZE = 254
ABSOLUTE_TRAMPOLINE_SIZE = 13
PADDED_TRAMPOLINE_SIZE = 16
SHORT_TRAMPOLINE_SIZE = 5

MAX_PAGE_DIST = pow(2, 25)

# global variables
master_lib_path = ""
inferior = None
dlopen = NULL
dlsym = NULL
dlclose = NULL

# simple enum for trampoline types
class TrampolineType(Enum):
    LONG_TRAMPOLINE = 0
    SHORT_TRAMPOLINE = 1

# check if GDB is attached to any process
# should be called in every script entry point
def is_attached() -> bool:
    return gdb.selected_inferior().pid != 0

# convert a python string to a corresponding C string
# should be used in every call of an inferior's function
def c_string(s: str) -> gdb.Value:
    tmp = s + '\0'
    buffer = bytearray(tmp.encode())
    return gdb.Value(buffer, gdb.lookup_type("char").array(len(buffer)-1))

# look up symbol symbol_name from file objfile_name
# currently not used due to a bug in GDB
def find_object_obj(symbol_name: str, objfile_name: str) -> gdb.Value:
    try:
        objfile = gdb.lookup_objfile(objfile_name)
        symbol = objfile.lookup_global_symbol(symbol_name).value()
    except:
        raise gdb.GdbError("Couldn't find symbol in object file.")
    else:
        return symbol

# search the current scope for symbol symbol_name
def find_object(symbol_name: str) -> gdb.Value:
    try:
        symbol = gdb.parse_and_eval(symbol_name)
    except:
        raise gdb.GdbError("Couldn't find symbol name.")
    else:
        return symbol

# search the object file objfile_name for the symbol symbol_name
def find_object_static(symbol_name: str, objfile_name: str) -> int:
    try:
        objfile = gdb.lookup_objfile(objfile_name)
        symbol = int(objfile.lookup_static_symbol(symbol_name).value().address)
    except:
        raise gdb.GdbError("Couldn't find symbol name in object file.")
    else:
        return symbol

# initialize global variables, e.g. dlopen, dlsym and check if GDB is attached
def init_global_vars():
    global inferior, dlopen, dlsym, dlclose
    if not is_attached():
        raise gdb.GdbError("No process attached.")
    inferior = gdb.selected_inferior()
    dlopen = find_object("dlopen")
    dlsym = find_object("dlsym")
    dlclose = find_object("dlclose")

# map address to the symbol name on the address using info symbol command
def addr_to_symbol(address: int) -> str:
    cmd = gdb.execute("info symbol %s" % str(address), to_string=True)
    match = re.match("No symbol matches .*\.", cmd)
    if match:
        return None
    result = cmd.split(' ')[0]
    match = re.match(".+@plt", result)
    if match:
        result = result.split('@')[0]
    return result

# define header structure
class struct_header:
    def __init__(self, magic: int, libhandle: int, trampoline_page_ptr: int, log_page_ptr: int, patch_backup_page_ptr: int, refcount: int, contains_log: bool, log_entries_count: int, patch_data_array_len: int, commands_len: int):
        self.magic = magic
        self.libhandle = libhandle
        self.trampoline_page_ptr = trampoline_page_ptr
        self.patch_backup_page_ptr = patch_backup_page_ptr
        self.log_page_ptr = log_page_ptr
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
        print(self.log_page_ptr)
        print(self.patch_backup_page_ptr)
        print(self.refcount)
        print(self.contains_log)
        print(self.log_entries_count)
        print(self.patch_data_array_len)
        print(self.commands_len)

#TODO check if lookup_static_symbol throws an exception ot returns None
#TODO objfile lookup is probably unnecessary
# read header from objfile_path file
def read_header(objfile_path: str) -> struct_header:
    patchlib = gdb.lookup_objfile(objfile_path)
    if patchlib is None:
        return None

    try:
        header_addr = find_object_static(PATCH_HEADER_VAR_NAME, objfile_path)
    except:
        return None
    buffer = inferior.read_memory(header_addr, HEADER_SIZE)
    magic = int.from_bytes(buffer[:4], BYTE_ORDER)
    if magic != MAGIC_CONSTANT:
        return None
    libhandle = int.from_bytes(buffer[4:12], BYTE_ORDER)
    trampoline_page_ptr = int.from_bytes(buffer[12:20], BYTE_ORDER)
    log_page_ptr = int.from_bytes(buffer[20:28], BYTE_ORDER)
    patch_backup_page_ptr = int.from_bytes(buffer[28:36], BYTE_ORDER)
    refcount = int.from_bytes(buffer[36:38], BYTE_ORDER)
    contains_log = int.from_bytes(buffer[38:40], BYTE_ORDER)
    if contains_log == 0:
        contains_log_bool = False
    elif contains_log == 1:
        contains_log_bool = True
    else:
        raise gdb.GdbError("Got wrong value for contains_log value.")
    log_entries_count = int.from_bytes(buffer[40:42], BYTE_ORDER)
    patch_data_array_len = int.from_bytes(buffer[42:44], BYTE_ORDER)
    commands_len = int.from_bytes(buffer[44:48], BYTE_ORDER)
    return struct_header(magic, libhandle, trampoline_page_ptr, log_page_ptr, patch_backup_page_ptr, refcount, contains_log, log_entries_count, patch_data_array_len, commands_len)

# write header to objfile_path file
def write_header(objfile_path: str, header: struct_header) -> None:
    if header.magic != MAGIC_CONSTANT:
        raise gdb.GdbError("Got wrong value of magic constant while trying to write header.")

    header_addr = find_object_static(PATCH_HEADER_VAR_NAME, objfile_path)

    buffer = bytearray()
    buffer.extend(header.magic.to_bytes(4, BYTE_ORDER))
    buffer.extend(header.libhandle.to_bytes(8, BYTE_ORDER))
    buffer.extend(header.trampoline_page_ptr.to_bytes(8, BYTE_ORDER))
    buffer.extend(header.log_page_ptr.to_bytes(8, BYTE_ORDER))
    buffer.extend(header.patch_backup_page_ptr.to_bytes(8, BYTE_ORDER))
    buffer.extend(header.refcount.to_bytes(2, BYTE_ORDER))
    if header.contains_log:
        tmp = 1
    else:
        tmp = 0
    buffer.extend(tmp.to_bytes(2, BYTE_ORDER))
    buffer.extend(header.log_entries_count.to_bytes(2, BYTE_ORDER))
    buffer.extend(header.patch_data_array_len.to_bytes(2, BYTE_ORDER))
    buffer.extend(header.commands_len.to_bytes(4, BYTE_ORDER))

    inferior.write_memory(header_addr, buffer, len(buffer))

# parse process mappings from info proc mappings command
# return a list containing allocated pages
def find_mappings() -> set[int]:
    mappings = gdb.execute("info proc mappings", to_string=True)
    mappings_list = re.findall(MAPPINGS_LINE_REGEX, mappings, re.MULTILINE)
    allocated_pages = set()
    for line in mappings_list:
        tmp = line.split()
        page = int(tmp[0], 16)
        size = int(tmp[2], 16)
        offset = 0
        while offset < size:
            allocated_pages.add(page + offset)
            offset += PAGE_SIZE
    return allocated_pages

# find the closest free page to the address
def find_nearest_free_page(address: int) -> int:
    current = address & PAGE_MASK
    allocated_pages = find_mappings()
    left = current - PAGE_SIZE
    right = current + PAGE_SIZE
    while left > 0 or right < 0x7fffffffffff:
        if left > 0:
            if abs(left - current) <= MAX_PAGE_DIST and left not in allocated_pages:
                return left
            left -= PAGE_SIZE

        if right < 0x7fffffffffff:
            if abs(right - current) <= MAX_PAGE_DIST and right not in allocated_pages:
                return right
            right += PAGE_SIZE

    return NULL

# fill bitmap in the trampoline page with zeros
def init_trampoline_bitmap(address: int):
    inferior.write_memory(address, bytearray(TRAMPOLINE_BITMAP_SIZE), TRAMPOLINE_BITMAP_SIZE)

# make a backup of all general purpose registers
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

# restore the values of the registers stored in registers dictionary
def restore_registers(registers: dict[str, int]):
    for reg in registers:
        gdb.execute("set $%s = %s" % (reg, str(registers[reg])))

# exec system call in the inferior process
def exec_syscall(syscall_number: int, arg1: int, arg2: int, arg3: int, arg4: int, arg5: int, arg6: int) -> int:
    if syscall_number < 0 or syscall_number > 332:
        raise gdb.GdbError("No such system call.")
    registers = save_registers()
    rip = registers["rip"]
    #align rip at the beginning of the page
    rip &= PAGE_MASK
    gdb.execute("set $rip = %s" % str(rip))
    syscall_instruction = bytearray.fromhex("0f 05")
    membackup = bytearray(inferior.read_memory(rip, 2))
    inferior.write_memory(rip, syscall_instruction, 2)
    #set register values
    gdb.execute("set $rax = %s" % str(syscall_number))
    gdb.execute("set $rdi = %s" % str(arg1))
    gdb.execute("set $rsi = %s" % str(arg2))
    gdb.execute("set $rdx = %s" % str(arg3))
    gdb.execute("set $r10 = %s" % str(arg4))
    gdb.execute("set $r8 = %s" % str(arg5))
    gdb.execute("set $r9 = %s" % str(arg6))
    gdb.execute("si")
    ret = int(gdb.parse_and_eval("$rax").cast(gdb.lookup_type("uint64_t")))
    restore_registers(registers)
    inferior.write_memory(rip, membackup, 2)
    return ret

# wrapper for mmap system call
def exec_mmap(address: int, size: int, prot: int, flags: int, fd: int, offset: int) -> int:
    return exec_syscall(SYS_MMAP, address, size, prot, flags, fd, offset)

# wrapper for munmap system call
def exec_munmap(address: int, size: int) -> int:
    return exec_syscall(SYS_MUNMAP, address, size, 0, 0, 0, 0)

# wrapper for mprotect system call
def exec_mprotect(address: int, size: int, prot: int) -> int:
    return exec_syscall(SYS_MPROTECT, address, size, prot, 0, 0, 0)

# allocate a trampoline page and initialize its bitmap
# check if it is not too far from the target_function_ptr
# when not able to allocate one, return NULL
def alloc_trampoline_page(page_base: int, target_function_ptr: int) -> int:
    ptr = exec_mmap(page_base, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)
    if ptr == -1:
        return NULL
    if abs(ptr - target_function_ptr) > (pow(2,31) - 1):
        exec_munmap(ptr, PAGE_SIZE)
        return NULL
    init_trampoline_bitmap(ptr)
    return ptr

# free the trampoline page
def free_trampoline_page(address: int):
    hdr = read_header(master_lib_path)
    hdr.trampoline_page_ptr = NULL
    write_header(master_lib_path, hdr)
    if exec_munmap(address, PAGE_SIZE) == -1:
        raise gdb.GdbError("Couldn't unmap the page.")

# search the trampoline bitmap and return current trampoline count
def get_trampoline_count(bitmap_address: int) -> int:
    buffer = bytearray(inferior.read_memory(bitmap_address, TRAMPOLINE_BITMAP_SIZE))
    counter = 0
    for word_index in range(TRAMPOLINE_BITMAP_SIZE):
        for bit in range(8):
            if (buffer[word_index] & (1 << bit)) != 0:
                counter += 1
    return counter

# find first free trampoline index in the trampoline bitmap
# set its bit to allocated
def find_first_free_trampoline_index(bitmap_address: int) -> int:
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

# allocate a trampoline in the trampoline page
# check if it is not too far from the target_function_address
def alloc_trampoline(target_function_address: int) -> int:
    hdr = read_header(master_lib_path)
    if hdr.trampoline_page_ptr == NULL:
        page_base = find_nearest_free_page(target_function_address)
        if page_base == NULL:
            return NULL
        ret = alloc_trampoline_page(page_base, target_function_address)
        if ret == NULL:
            return NULL
        hdr.trampoline_page_ptr = ret
        write_header(master_lib_path, hdr)
    else:
        #TODO validate this
        #abort if the function is too far from the already allocated trampoline page
        if abs(target_function_address - hdr.trampoline_page_ptr) > (pow(2, 31) - 1):
            return NULL
    index = find_first_free_trampoline_index(hdr.trampoline_page_ptr)
    if index == -1:
        return NULL
    return hdr.trampoline_page_ptr + TRAMPOLINE_BITMAP_SIZE + index*PADDED_TRAMPOLINE_SIZE

# free trampoline at trampoline_address address
def free_trampoline(trampoline_address: int):
    hdr = read_header(master_lib_path)
    if hdr.trampoline_page_ptr == NULL:
        return
    index = int((trampoline_address - hdr.trampoline_page_ptr - TRAMPOLINE_BITMAP_SIZE) / PADDED_TRAMPOLINE_SIZE)
    word_index = int(index / 8)
    bit_index = index % 8
    buffer = bytearray(inferior.read_memory(hdr.trampoline_page_ptr, TRAMPOLINE_BITMAP_SIZE))
    #reset bit
    buffer[word_index] &= (~(1 << bit_index))
    inferior.write_memory(hdr.trampoline_page_ptr, buffer, len(buffer))

# helper function to free the trampoline that the instruction at instruction_ptr points to
def free_trampoline_from_instruction(instruction_ptr: int):
    instruction_ptr += 1
    relative_offset = int.from_bytes(bytearray(inferior.read_memory(instruction_ptr, SHORT_TRAMPOLINE_SIZE - 1)), BYTE_ORDER, signed=True)
    free_trampoline(instruction_ptr + SHORT_TRAMPOLINE_SIZE + relative_offset)

# get the first byte of the instruction at addr address
def get_instruction_prefix(addr: int) -> int:
    tmp = bytearray(inferior.read_memory(addr, 1))
    return tmp[0]

# find a symbol address in objfile_name file using dlsym function in the inferior
def find_object_dlsym(symbol_name: str, objfile_name: str) -> int:
    hdr = read_header(objfile_name)
    if hdr is None:
        return NULL
    libhandle = hdr.libhandle
    symbol_address = int(dlsym(libhandle, c_string(symbol_name)).cast(gdb.lookup_type("uint64_t")))
    if symbol_address == NULL:
        raise gdb.GdbError("Couldn't find symbol name.")
    return symbol_address

# allocate memory for the log
# write corresponding pointers to the master library header
def alloc_log_storage() -> bool:
    hdr = read_header(master_lib_path)
    hdr.log_page_ptr = exec_mmap(NULL, LOG_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)
    if hdr.log_page_ptr == -1:
        return False
    hdr.patch_backup_page_ptr = exec_mmap(NULL, PATCH_BACKUP_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)
    if hdr.patch_backup_page_ptr == -1:
        exec_munmap(hdr.log_page_ptr, LOG_SIZE)
        return False
    write_header(master_lib_path, hdr)
    return True

# free memory occupied by the log
# if no log is allocated the function should ignore it
def free_log_storage():
    hdr = read_header(master_lib_path)
    if hdr.log_page_ptr != NULL:
        exec_munmap(hdr.log_page_ptr, LOG_SIZE)
    if hdr.patch_backup_page_ptr != NULL:
        exec_munmap(hdr.patch_backup_page_ptr, PATCH_BACKUP_SIZE)

#define structure for log entry
class struct_log_entry:
    def __init__(self,
        target_func_ptr: int,  # target function pointer
        patch_func_ptr: int,   # patch function pointer
        patch_type: str,       # type of patch procedure performed
        timestamp: int,        # timestamp
        path_offset: int,      # offset of the patch library path string in section for variable length data
        is_active: bool,       # indicates whether the patch is active
        membackup_offset: int, # offset of the memory backup in section for variable length data
        path_len: int,         # length of the patch lirbary path string
        membackup_len: int):   # length of the memory backup
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

    # returns a string representing the log entry
    def to_string(self):
        global master_lib_path
        hdr = read_header(master_lib_path)
        backup_ptr = hdr.patch_backup_page_ptr
        if backup_ptr == NULL:
            path = ""
        else:
            backup_ptr += self.path_offset
            path = bytearray(inferior.read_memory(backup_ptr, self.path_len)).decode("ascii")

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

# converts log entry in raw byte form to a list of log entries
def bytearray_to_log_entry(buffer: bytearray) -> struct_log_entry:
    target_func_ptr = int.from_bytes(buffer[0:8], BYTE_ORDER)
    patch_func_ptr = int.from_bytes(buffer[8:16], BYTE_ORDER)
    patch_type = int.from_bytes(buffer[16:17], BYTE_ORDER)
    if patch_type == 0:
        patch_type_str = "O"
    else:
        patch_type_str = "L"
    timestamp = int.from_bytes(buffer[17:21], BYTE_ORDER)
    path_offset = int.from_bytes(buffer[21:25], BYTE_ORDER)
    is_active_int = int.from_bytes(buffer[25:27], BYTE_ORDER)
    if is_active_int == 0:
        is_active = False
    elif is_active_int == 1:
        is_active = True
    else:
        raise gdb.GdbError("Got wrong value of is_active")

    membackup_offset = int.from_bytes(buffer[27:29], BYTE_ORDER)
    path_len = int.from_bytes(buffer[29:31], BYTE_ORDER)
    membackup_len = int.from_bytes(buffer[31:32], BYTE_ORDER)
    return struct_log_entry(target_func_ptr, patch_func_ptr, patch_type_str, timestamp, path_offset, is_active, membackup_offset, path_len, membackup_len)

# read log entry at index
def read_log_entry(index: int) -> struct_log_entry:
    global master_lib_path
    header = read_header(master_lib_path)
    if index >= header.log_entries_count:
        return None

    log_address = header.log_page_ptr
    log_address += index*LOG_ENTRY_SIZE
    buffer = bytearray(inferior.read_memory(log_address, LOG_ENTRY_SIZE))
    return bytearray_to_log_entry(buffer)

# converts struct_log_entry object to raw bytes
def log_entry_to_bytearray(log_entry: struct_log_entry) -> bytearray:
    log_entry_buf = bytearray()
    log_entry_buf.extend(log_entry.target_func_ptr.to_bytes(8, BYTE_ORDER))
    log_entry_buf.extend(log_entry.patch_func_ptr.to_bytes(8, BYTE_ORDER))
    if log_entry.patch_type == "O":
        tmp = 0
    elif log_entry.patch_type == "L":
        tmp = 1
    else:
        tmp = 255

    log_entry_buf.extend(tmp.to_bytes(1, BYTE_ORDER))
    log_entry_buf.extend(log_entry.timestamp.to_bytes(4, BYTE_ORDER))
    log_entry_buf.extend(log_entry.path_offset.to_bytes(4, BYTE_ORDER))
    if log_entry.is_active:
        tmp = 1
    else:
        tmp = 0
    log_entry_buf.extend(tmp.to_bytes(2, BYTE_ORDER))
    log_entry_buf.extend(log_entry.membackup_offset.to_bytes(2, BYTE_ORDER))
    log_entry_buf.extend(log_entry.path_len.to_bytes(2, BYTE_ORDER))
    log_entry_buf.extend(log_entry.membackup_len.to_bytes(1, BYTE_ORDER))
    return log_entry_buf

# write log entry at index
def write_log_entry(log_entry: struct_log_entry, index: int) -> None:
    global master_lib_path
    header = read_header(master_lib_path)
    log_ptr = header.log_page_ptr
    log_ptr += index*LOG_ENTRY_SIZE

    log_entry_buf = log_entry_to_bytearray(log_entry)
    inferior.write_memory(log_ptr, log_entry_buf, len(log_entry_buf))

# convert whole log in raw bytes form to a list of log entries
def log_to_entry_array() -> list[struct_log_entry]:
    hdr = read_header(master_lib_path)
    result = list()
    if hdr.log_page_ptr == NULL:
        return result
    buffer = bytearray(inferior.read_memory(hdr.log_page_ptr, hdr.log_entries_count*LOG_ENTRY_SIZE))
    for i in range(hdr.log_entries_count):
        result.append(bytearray_to_log_entry(buffer[(i*LOG_ENTRY_SIZE):((i+1)*LOG_ENTRY_SIZE)]))
    return result

# convert list of log entries to raw bytes and write the log
def entry_array_to_log(entries: list[struct_log_entry]):
    hdr = read_header(master_lib_path)
    if hdr.log_page_ptr == NULL:
        return
    buffer = bytearray()
    for entry in entries:
        buffer.extend(log_entry_to_bytearray(entry))
    inferior.write_memory(hdr.log_page_ptr, buffer, len(buffer))

def get_last_log_entry() -> struct_log_entry:
    global master_lib_path
    hdr = read_header(master_lib_path)
    if hdr.log_entries_count <= 0:
        return None
    return read_log_entry(hdr.log_entries_count - 1)

# define structure representing variable length metadata from log entry
class struct_patch_backup:
    def __init__(self, path: str, membackup: bytearray):
        self.path = path            # path to the patch library
        self.membackup = membackup  # memory overwritten by a trampoline or backed up got entry

    # return size of the whole object
    def size(self) -> int:
        result = 0
        if self.path is not None:
            result += len(self.path)
        if self.membackup is not None:
            result += len(self.membackup)
        return result

# read variable length metadata for the corresponding log entry
def read_log_entry_data(log_entry: struct_log_entry) -> struct_patch_backup:
    global master_lib_path
    path = None
    membackup = None
    header = read_header(master_lib_path)
    log_data_ptr = header.patch_backup_page_ptr
    if log_data_ptr == NULL:
        return None
    if log_entry.path_len != 0:
        path = bytearray(inferior.read_memory(log_data_ptr + log_entry.path_offset, log_entry.path_len)).decode("ascii")
    if log_entry.membackup_len != 0:
        membackup = bytearray(inferior.read_memory(log_data_ptr + log_entry.membackup_offset, log_entry.membackup_len))
    return struct_patch_backup(path, membackup)

# add new log entry to the log
def add_log_entry(log_entry: struct_log_entry, patch_backup: struct_patch_backup) -> None:
    global master_lib_path
    header = read_header(master_lib_path)
    if header.log_page_ptr == NULL or header.patch_backup_page_ptr == NULL:
        if not alloc_log_storage():
            print("Couldn't allocate memory for the log.")
            return None
    header = read_header(master_lib_path)
    index = header.log_entries_count
    patch_backup_ptr = header.patch_backup_page_ptr
    log_size = header.log_entries_count*LOG_ENTRY_SIZE
    backup_size = header.patch_data_array_len
    patch_backup_ptr += backup_size
    if log_size + LOG_ENTRY_SIZE > LOG_SIZE or backup_size + patch_backup.size() > PATCH_BACKUP_SIZE:
        print("The log is full.")
        return None
    offset = header.patch_data_array_len
    #update header
    header.log_entries_count += 1
    header.patch_data_array_len += patch_backup.size()
    write_header(master_lib_path, header)

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
    entries = log_to_entry_array()
    result = None
    i = len(entries) - 1
    while i >= 0:
        entry = entries[i]
        if entry.is_active and entry.target_func_ptr == func_address:
            result = read_log_entry_data(entry).path
            instruction_prefix = get_instruction_prefix(entry.target_func_ptr)
            if instruction_prefix == 0xe9:
                free_trampoline_from_instruction(entry.target_func_ptr)
            entry.is_active = False
            write_log_entry(entry, i)
            break
        i -= 1
    return result

# find first patch patching the function at func_address address
def find_first_patch(func_address: int) -> struct_log_entry:
    global master_lib_path
    entries = log_to_entry_array()
    for entry in entries:
        if entry.target_func_ptr == func_address:
            return entry
    return None

# copy the log to another patch library
def copy_log(dest: str, src: str):
    global master_lib_path
    src_hdr = read_header(src)
    dest_hdr = read_header(dest)
    dest_hdr.contains_log = True
    dest_hdr.log_entries_count = src_hdr.log_entries_count
    dest_hdr.patch_data_array_len = src_hdr.patch_data_array_len
    dest_hdr.trampoline_page_ptr = src_hdr.trampoline_page_ptr
    dest_hdr.log_page_ptr = src_hdr.log_page_ptr
    dest_hdr.patch_backup_page_ptr = src_hdr.patch_backup_page_ptr
    write_header(dest, dest_hdr)
    src_hdr.contains_log = False
    src_hdr.trampoline_page_ptr = NULL
    src_hdr.log_page_ptr = NULL
    src_hdr.log_page_ptr = NULL
    write_header(src, src_hdr)
    master_lib_path = dest

# close patch library lib
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
                break
    if is_last:
        if hdr.trampoline_page_ptr != NULL:
            free_trampoline_page(hdr.trampoline_page_ptr)
        if hdr.log_page_ptr != NULL or hdr.patch_backup_page_ptr != NULL:
            free_log_storage()
        master_lib_path = ""
    dlclose(hdr.libhandle)

# decrease reference count of lib patch library
def decrease_refcount(lib: str):
    hdr = read_header(lib)
    hdr.refcount -= 1
    write_header(lib, hdr)
    if hdr.refcount <= 0:
        close_lib(lib)

# steal the reference count of the active library for func_address function
# add it to the new library
def steal_refcount(func_address: int, current_lib: str):
    lib = find_last_patch_and_set_as_inactive(func_address)
    if lib is not None:
        pass
        decrease_refcount(lib)

    current = read_header(current_lib)
    current.refcount += 1
    write_header(current_lib, current)

# find the master library
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

# define structure representing absolute trampoline
class AbsoluteTrampoline:
    def __init__(self):
       self.trampoline = bytearray.fromhex("49 bb 00 00 00 00 00 00 00 00 41 ff e3")

    def size(self) -> int:
        return len(self.trampoline)

    # write the jump address addr to the trampoline
    def complete_address(self, addr: bytearray):
        for i in range(8):
            self.trampoline[i+2] = addr[i]

    # write the trampoline in the memory at address
    def write_trampoline(self, address: int):
        inferior.write_memory(address, self.trampoline, len(self.trampoline))

# AbsoluteTrampoline aligned to 16 bytes padded with 3 nop instructions
class AlignedAbsoluteTrampoline(AbsoluteTrampoline):
    def __init__(self):
        self.trampoline = bytearray.fromhex("49 bb 00 00 00 00 00 00 00 00 41 ff e3 90 90 90")

# define structure representing relative trampoline
class RelativeTrampoline:
    def __init__(self):
        self.trampoline = bytearray.fromhex("e9 00 00 00 00")

    def size(self) -> int:
        return len(self.trampoline)

    #write the jump offset address to the trampoline
    def complete_address(self, address: int):
        offset = address.to_bytes(4, BYTE_ORDER, signed=True)
        for i in range(4):
            self.trampoline[i+1] = offset[i]

    # write the trampoline in the memory at address
    def write_trampoline(self, address: int):
        inferior.write_memory(address, self.trampoline, len(self.trampoline))

# perform patching of own function
# fall back to the absolute trampoline in case the short one cannot be used
def do_patch_own(target_addr: int, patch_addr: int, path: str, path_offset: int, path_len: int, membackup_offset: int, membackup_len: int, mark_log_entry: bool, trampoline_type: TrampolineType):
    #control flow must not be where the trampoline is about to be inserted
    #TODO control flow must not be in the function, it may lead to crash
    rip = int(gdb.parse_and_eval("$rip").cast(gdb.lookup_type("uint64_t")))
    if rip >= target_addr and rip < target_addr + 13:
        raise gdb.GdbError("The code segment where the trampoline is about to be inserted is being executed.")

    patch_addr_arr = patch_addr.to_bytes(8, byteorder = BYTE_ORDER)

    #steal refcount
    steal_refcount(target_addr, path)
    #write to log
    if mark_log_entry:
        entry = struct_log_entry(target_addr, patch_addr, "O", int(time.time()), 0, True, 0, 0, 0)
        backup = struct_patch_backup(None, None)
        if path_offset != -1:
            entry.path_offset = path_offset
            entry.path_len = path_len
        else:
            backup.path = path
            entry.path_len = len(path)

        tmp = find_first_patch(target_addr)
        if tmp is None:
            backup.membackup = bytearray(inferior.read_memory(target_addr, ABSOLUTE_TRAMPOLINE_SIZE))
            entry.membackup_len = len(backup.membackup)
        else:
            entry.membackup_offset = tmp.membackup_offset
            entry.membackup_len = tmp.membackup_len

    #write trampoline
    if trampoline_type == TrampolineType.LONG_TRAMPOLINE:
        ret = NULL
    elif trampoline_type == TrampolineType.SHORT_TRAMPOLINE:
        ret = alloc_trampoline(target_addr)
        if ret == NULL:
            print("Couldn't allocate a trampoline, falling back to the absolute trampoline.")
    else:
        raise gdb.GdbError("Got wrong type of trampoline.")
    if ret == NULL:
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
    if mark_log_entry:
        add_log_entry(entry, backup)

# perform patching library functions
def do_patch_lib(target_ptr: int, patch: int, path: str, path_offset: int, path_len: int, membackup_offset: int, membackup_len: int, mark_log_entry: bool):
    #fetch relative offset
    relative_addr = int.from_bytes(inferior.read_memory(target_ptr + 2, 4), BYTE_ORDER, signed=True)

    #fetch next instruction's address
    next_instruction = target_ptr + 6

    #calculate got.plt entry
    addr_got = next_instruction + relative_addr
    patch_arr = patch.to_bytes(8, byteorder = BYTE_ORDER)

    #steal refcount
    steal_refcount(target_ptr, path)

    #write to log
    if mark_log_entry:
        entry = struct_log_entry(target_ptr, patch, "L", int(time.time()), 0, True, 0, 0, 0)
        backup = struct_patch_backup(None, None)
        if path_offset != -1:
            entry.path_offset = path_offset
            entry.path_len = path_len
        else:
            backup.path = path
            entry.path_len = len(path)

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

# find the first log entry representing a patch from the library path
def find_first_log_lib(path: str) -> struct_log_entry:
    entries = log_to_entry_array()
    for entry in entries:
        data = read_log_entry_data(entry)
        if data.path == path:
            return entry
    return None

# define class representing GDB command invoked to perform a patch
# Parameters:
#
# path to patch library
# optional: '--log'
# by default no logging is done unless the second parameter is specified
class Patch (gdb.Command):
    "Patch functions."

    type_dict = {}

    def __init__(self):
        super(Patch, self).__init__("patch", gdb.COMMAND_USER)

    # check if the metadata in the patch library is valid
    # return list of tuples representing the patch instructions
    # the tuples are as follows (patch type, trampoline type, target function address, patch function address)
    def check_patch_metadata(self, instructions: list[list[str]], path: str) -> list[tuple[str, str, int, int]]:
        result = []
        # only own or library functions are valid options
        # only short, absolute or no trampolines are valid options
        for instruction in instructions:
            if instruction[0] != 'O' and instruction[0] != 'L':
                return None
            if instruction[1] != 'L' and instruction[1] != 'S' and instruction[1] != 'N':
                return None

        for instruction in instructions:
            # check if patch function specified in the instructions is present in the library
            patch_func = instruction[3]
            try:
                patch_ptr = find_object_dlsym(patch_func, path)
            except:
                return None

            # check if target function symbol is present in the target process
            target_func = instruction[2]
            if instruction[0] == 'O':
                # the user can specify the address directly
                match = re.match(HEX_REGEX, target_func)
                if match is not None:
                    target_ptr = int(target_func, 16)
                else:
                    try:
                        target_ptr = int(find_object(target_func).cast(gdb.lookup_type("uint64_t")))
                    except:
                        return None
            else:
                try:
                    target = "'%s@plt'" % target_func
                    target_ptr = int(find_object(target).cast(gdb.lookup_type("uint64_t")))
                except:
                    return None

            result.append((instruction[0], instruction[1], target_ptr, patch_ptr))
        return result

    # read patch instruction/metadata from the patch library
    def extract_patch_metadata(self, objfile: str) -> list[list[str]]:
        header = read_header(objfile)
        if header is None:
            print("Couldn't find patch header.")
            return None
        commands_len = header.commands_len
        commands = find_object_dlsym(PATCH_COMMANDS_VAR_NAME, objfile)

        items = inferior.read_memory(commands, commands_len).tobytes().decode().split(";")
        result = []
        for item in items:
            #string is split by ';', the last element is empty
            if not item:
                continue
            result.append(item.split(":"))
        return result

    # check if essential types are present in the target process
    def is_patchable(self):
        try:
            for t in type_list:
                self.type_dict[t] = gdb.lookup_type(t)
        except:
            raise gdb.GdbError("Required types were not supported.")
 
    #magic constant checking is in read_header function
    # open the patch library using dlopen function
    def load_patch_lib(self, path: str):
        self.dlopen_ret = dlopen(c_string(path), 2)
        if self.dlopen_ret == NULL:
            raise gdb.GdbError("Couldn't open the patch library.")
        header = read_header(path)
        if header is None:
            raise gdb.GdbError("Object file has a wrong format.")
        header.libhandle = int(self.dlopen_ret.cast(gdb.lookup_type("uint64_t")))
        write_header(path, header)

    # API method which ensures the path to the patch library is completed in shell
    def complete(self, text, word):
        return gdb.COMPLETE_FILENAME

    # API method which is called when the user invokes the command
    def invoke(self, arg, from_tty):
        global master_lib_path
        self.type_dict.clear()
        argv = gdb.string_to_argv(arg)
        if len(argv) != 1 and len(argv) != 2:
            raise gdb.GdbError("patch takes one or two parameter")

        mark_log_entry = False
        if len(argv) == 2:
            if argv[1] != "--log":
                return
            mark_log_entry = True

        #find necessary objects
        init_global_vars()
        self.is_patchable()
        find_master_lib()

        self.load_patch_lib(argv[0])
        metadata = self.extract_patch_metadata(argv[0])
        if metadata is None:
            dlclose(self.dlopen_ret)
            raise gdb.GdbError("The library has invalid data.")
        patch_commands = self.check_patch_metadata(metadata, argv[0])
        if patch_commands is None:
            dlclose(self.dlopen_ret)
            raise gdb.GdbError("The library has invalid data.")
        if not master_lib_path:
            master_lib_path = argv[0]
        tmp = read_header(master_lib_path)
        tmp.contains_log = True
        write_header(master_lib_path, tmp)

        first_entry = None

        for patch in patch_commands:
            target_func = patch[2]
            patch_func = patch[3]
            if patch[1] == "L":
                trampoline_type = TrampolineType.LONG_TRAMPOLINE
            elif patch[1] == "S":
                trampoline_type = TrampolineType.SHORT_TRAMPOLINE

            if first_entry is None:
                first_entry = find_first_log_lib(argv[0])

            if patch[0] == 'O':
                #the first entry to be logged
                if first_entry is None:
                    do_patch_own(target_func, patch_func, argv[0], -1, 0, -1, 0, mark_log_entry, trampoline_type)
                #copy the references from the first entry from this library, i.e. first_entry
                else:
                    do_patch_own(target_func, patch_func, argv[0], first_entry.path_offset, first_entry.path_len, -1, 0, mark_log_entry, trampoline_type)
            elif patch[0] == 'L':
                #the first entry to be logged
                if first_entry is None:
                    do_patch_lib(target_func, patch_func, argv[0], -1, 0, -1, 0, mark_log_entry)
                #copy the references from the first entry from this library, i.e. first_entry
                else:
                    do_patch_lib(target_func, patch_func, argv[0], first_entry.path_offset, first_entry.path_len, -1, 0, mark_log_entry)

#WARNING!!! sets found library as inactive
#TODO poor design
def find_active_entry_and_set_as_inactive(func_address: int) -> struct_log_entry:
    global master_lib_path
    entries = log_to_entry_array()
    result = None
    i = 0
    while i < len(entries):
        entry = entries[i]
        if entry.target_func_ptr == func_address and entry.is_active:
            instruction_prefix = get_instruction_prefix(entry.target_func_ptr)
            if instruction_prefix == 0xe9:
                free_trampoline_from_instruction(entry.target_func_ptr)
            entry.is_active = False
            write_log_entry(entry, i)
            return entry
        i += 1
    return None

# define structure representing a command which performs reapplication of an incative patch
# or reverts an active patch, i.e. restores the state from before the patch application
#
# Parameters:
#
# number specifying the the index of a log entry in the log
# special parameter: 0 represents patch reversion, by default every active patch is reverted
# optional: a list of functions to be reverted might be specified with the special parameter
class ReapplyPatch(gdb.Command):
    def __init__(self):
        super(ReapplyPatch, self).__init__("patch-reapply", gdb.COMMAND_USER)

    # this method reverts all active patches that were logged
    def revert_all(self):
        entries = log_to_entry_array()
        for i in range(len(entries)):
            entry = entries[i]
            if not entry.is_active:
                continue
            entry.is_active = False
            backup = read_log_entry_data(entry)
            if backup.path is None or backup.membackup is None:
                raise gdb.GdbError("Cannot find memory backup or path.")
            if entry.patch_type == "O":
                instruction_prefix = get_instruction_prefix(entry.target_func_ptr)
                if instruction_prefix == 0xe9:
                    free_trampoline_from_instruction(entry.target_func_ptr)

                inferior.write_memory(entry.target_func_ptr, backup.membackup, len(backup.membackup))
            elif entry.patch_type == "L":
                instruction = entry.target_func_ptr + 2
                relative_offset = int.from_bytes(inferior.read_memory(instruction, 4), BYTE_ORDER, signed=True)
                got_entry = entry.target_func_ptr + 6 + relative_offset
                inferior.write_memory(got_entry, backup.membackup, len(backup.membackup))

            write_log_entry(entry, i)
            decrease_refcount(backup.path)

    # revert patches specified as arguments
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
                    function_address = int(find_object("'%s@plt'" % argv[i]).cast(gdb.lookup_type("uint64_t")))
                except:
                    raise gdb.GdbError("Nothing to revert.")
                entry = find_active_entry_and_set_as_inactive(function_address)
                if entry is None:
                    raise gdb.GdbError("Nothing to revert.")
            backup = read_log_entry_data(entry)
            path = backup.path
            membackup = backup.membackup
            if path is None or membackup is None:
                raise gdb.GdbError("Fatal error, couldn't find membackup.")
            if entry.patch_type == "O":
                instruction_prefix = get_instruction_prefix(entry.target_func_ptr)
                if instruction_prefix == 0xe9:
                    free_trampoline_from_instruction(entry.target_func_ptr)
                inferior.write_memory(function_address, membackup, len(membackup))
            elif entry.patch_type == "L":
                instruction = function_address + 2
                relative_offset = int.from_bytes(bytearray(inferior.read_memory(instruction, 4)), BYTE_ORDER, signed=True)
                got_entry = function_address + 6 + relative_offset
                inferior.write_memory(got_entry, membackup, len(membackup))

            decrease_refcount(backup.path)
            i += 1

    # API method called when the user invokes the command
    # takes a number and optionally a list as parameters
    def invoke(self, arg, from_tty):
        global master_lib_path
        argv = gdb.string_to_argv(arg)
        if len(arg) < 1:
           raise gdb.GdbError("patch-reapply takes one parameter")

        init_global_vars()
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

        steal_refcount(log_entry.target_func_ptr, data.path)
        if log_entry.patch_type == "O":
            ret = alloc_trampoline(log_entry.target_func_ptr)
            if ret == NULL:
                print("Couldn't allocate a trampoline, falling back to the absolute trampoline.")
                trampoline = AbsoluteTrampoline()
                trampoline.complete_address(bytearray(log_entry.patch_func_ptr.to_bytes(8, BYTE_ORDER)))
                trampoline.write_trampoline(log_entry.target_func_ptr)
            else:
                long_trampoline = AlignedAbsoluteTrampoline()
                short_trampoline = RelativeTrampoline()
                long_trampoline.complete_address(log_entry.patch_func_ptr.to_bytes(8, BYTE_ORDER))
                long_trampoline.write_trampoline(ret)
                relative_offset = ret - log_entry.target_func_ptr - SHORT_TRAMPOLINE_SIZE
                short_trampoline.complete_address(relative_offset)
                short_trampoline.write_trampoline(log_entry.target_func_ptr)

        elif log_entry.patch_type == "L":
            instruction_ptr = log_entry.target_func_ptr + 2
            relative_offset = int.from_bytes(bytearray(inferior.read_memory(instruction_ptr, 4)), BYTE_ORDER, signed=True)
            instruction_ptr += 4
            got_entry = instruction_ptr + relative_offset
            inferior.write(log_entry.patch_func_ptr.to_bytes(8, BYTE_ORDER))

        log_entry.is_active = True
        write_log_entry(log_entry, index)

# convert the whole log to a string
def log_to_string() -> str:
    entries = log_to_entry_array()
    result = "[0] revert"
    i = 1
    for entry in entries:
        result = "".join([result, "\n", "[", str(i), "]", entry.to_string()])
        i += 1
    return result

# define a structure representing a command which prints the log
# No parameters
class PatchLog(gdb.Command):
    def __init__(self):
        super(PatchLog, self).__init__("patch-log", gdb.COMMAND_USER)

    # API method called when the user invokes the command
    def invoke(self, arg, from_tty):
        global master_lib_path
        argv = gdb.string_to_argv(arg)
        if len(argv) != 0:
            raise gdb.GdbError("patch-log takes no parameters")

        init_global_vars()
        find_master_lib()
        if not master_lib_path:
            print("Couldn't find the log. No patch applied.")
            return
        print(log_to_string())

# define a structure representing a command
#
# Parameters:
#
# path to the destination file
class PatchLogDump(gdb.Command):
    def __init__(self):
        super(PatchLogDump, self).__init__("patch-dump", gdb.COMMAND_USER)

    # API method called when the user invokes the command
    # takes one argument - the file path
    def invoke(self, arg, from_tty):
        global master_lib_path
        argv = gdb.string_to_argv(arg)

        init_global_vars()
        if len(argv) != 1:
            raise gdb.GdbError("Provide a file name.")

        find_master_lib()
        if not master_lib_path:
            raise gdb.GdbError("Couldn't find master library.")

        #open file
        file = open(argv[0], "w+")

        file.write(log_to_string())
        file.close()

# create instances of the commands
# required by GDB python API
Patch()
PatchLog()
ReapplyPatch()
PatchLogDump()

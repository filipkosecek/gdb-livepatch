import gdb

type_list = ["char", "uint64_t", "int32_t"]

def find_patch_section_range(section_name: str, object_path: str) -> tuple[int, int]:
    output = gdb.execute("maintenance info sections -all-objects " + section_name, False, True)
    items = output.split("Object file:")
    for item in items:
        if item.find(object_path) != -1:
            tmp = item
            break
    if not tmp:
        raise gdb.GdbError("Couldn't find " + object_path + " object.")

    index = tmp.find(section_name)
    #find delimiter of section range
    while index >= 0 and (tmp[index] != '-' or tmp[index+1] != '>'):
        index -= 1
    if index < 0:
        gdb.GdbError("Couldn't find section address.")

    #find section base address
    section_beg_index = index
    while section_beg_index >= 0 and tmp[section_beg_index] != 'x':
        section_beg_index -= 1
    if section_beg_index < 0:
        gdb.GdbError("Couldn't find section address")
    section_beg_index += 1

    #copy section base address bytes and convert to int
    section_beg = ""
    while tmp[section_beg_index] != '-':
        section_beg += tmp[section_beg_index]
        section_beg_index += 1

    #find section end address
    section_end_index = index
    while tmp[section_end_index] != 'x':
        section_end_index += 1
    section_end_index += 1

    #build string
    section_end = ""
    while tmp[section_end_index] != ' ':
        section_end += tmp[section_end_index]
        section_end_index += 1

    beg = int(section_beg, base=16)
    end = int(section_end, base=16)
    return beg, end - beg

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

    def write_backup(self, address: int):
        pass

    #this function writes a 32 byte block into .patch.backup section of patch library
    #size of memcontent may vary hence padding_size
    def write_backup(self, address: int, dest: int,  padding_size: int):
        buffer = bytearray()
        buffer.extend(dest.to_bytes(8, byteorder="little"))
        padding = bytearray(padding_size)
        padding[0] = padding_size
        buffer.extend(padding)
        buffer.extend(self.membackup)
        inferior = gdb.selected_inferior()
        inferior.write_memory(address, buffer, len(buffer))

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

    def write_backup(self, address: int):
        super().write_backup(address, self.target_addr, 3)

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

    def write_backup(self, address: int):
        super().write_backup(address, self.addr_got, 8)

class Patch (gdb.Command):
    "Patch your functions."

    type_dict = {}

    def __init__(self):
        super(Patch, self).__init__("patch", gdb.COMMAND_USER)

    def extract_patch_metadata(self, section_beg: int, data_length: int) -> list[list[str]]:
        inferior = gdb.selected_inferior()
        items = inferior.read_memory(section_beg, data_length).tobytes().decode().split(";")
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
 
    def load_patch_lib(self, path: str):
        self.dlopen_ret = self.dlopen_addr(path, 2)
        if self.dlopen_ret == 0:
            raise gdb.GdbError("Couldn't open the patch library.")

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
        if len(argv) != 2:
            raise gdb.GdbError("patch own takes two parameters")

        #find necessary objects
        self.dlopen_addr = find_object("dlopen")
        self.dlclose_addr = find_object("dlclose")
        self.is_patchable()

        if argv[1] == "T":
            self.load_patch_lib(argv[0])
            span = find_patch_section_range(".patch", argv[0])
            #we assume the last character is terminating 0
            metadata = self.extract_patch_metadata(span[0], span[1]-1)

            base = find_patch_section_range(".patch.backup", argv[0])[0]
            index = 0

            inferior = gdb.selected_inferior()
            lib_handle = int(self.dlopen_ret.cast(gdb.lookup_type("uint64_t")))
            buffer = bytearray(lib_handle.to_bytes(8, byteorder="little"))
            inferior.write_memory(base, buffer, len(buffer))
            base += len(buffer)

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
                self.strategy.write_backup(base + index*24)
                index += 1

        elif argv[1] == "R":
            self.clean(argv[0])
        else:
           raise gdb.GdbError("Unrecognized option.") 

Patch()

import gdb

type_list = ["char", "uint64_t", "int32_t"]

def find_patch_section_range(section_name: str) -> tuple[int, int]:
    output = gdb.execute("maintenance info sections -all-objects " + section_name, False, True)
    index = output.find(section_name)
    #find delimiter of section range
    while index >= 0 and (output[index] != '-' or output[index+1] != '>'):
        index -= 1
    if index < 0:
        gdb.GdbError("Couldn't find section address.")

    #find section base address
    section_beg_index = index
    while section_beg_index >= 0 and output[section_beg_index] != 'x':
        section_beg_index -= 1
    if section_beg_index < 0:
        gdb.GdbError("Couldn't find section address")
    section_beg_index += 1

    #copy section base address bytes and convert to int
    section_beg = ""
    while output[section_beg_index] != '-':
        section_beg += output[section_beg_index]
        section_beg_index += 1

    #find section end address
    section_end_index = index
    while output[section_end_index] != 'x':
        section_end_index += 1
    section_end_index += 1

    #build string
    section_end = ""
    while output[section_end_index] != ' ':
        section_end += output[section_end_index]
        section_end_index += 1

    beg = int(section_beg, base=16)
    end = int(section_end, base=16)
    #assuming there is a null terminating character
    return beg, end - beg - 1

def find_object(obj: str) -> gdb.Value:
    try:
        obj_addr = gdb.parse_and_eval(obj)
    except:
        raise gdb.GdbError("Couldn't find " + obj + ".")
    else:
        return obj_addr

class AbsoluteTrampoline:
    def __init__(self):
       self.trampoline = bytearray.fromhex("49 bb 00 00 00 00 00 00 00 00 41 ff e3")

    def complete_address(self, addr: bytearray):
        for i in range(8):
            self.trampoline[i+2] = addr[i]

    def write_trampoline(self, address: gdb.Value):
        inferior = gdb.selected_inferior()
        inferior.write_memory(address, self.trampoline, 13)

class PatchStrategy:
    def __init__(self, lib_handle: gdb.Value, dlclose: gdb.Value, target_func: str, patch_func: str):
        self.lib_handle = lib_handle
        self.dlclose = dlclose
        self.target_func = target_func
        self.patch_func = patch_func

    def do_patch(self):
        pass
    
    def clean(self):
        pass

class PatchOwnStrategy (PatchStrategy):
    def __init__(self, lib_handle: gdb.Value, dlclose: gdb.Value, target_func: str, patch_func: str):
        super().__init__(lib_handle, dlclose, target_func, patch_func)

    def do_patch(self):
        try:
            target_addr = find_object(self.target_func)
        except:
            self.clean()
            raise gdb.GdbError("Couldn't find target function symbol.")

        #control flow must not be where the trampoline is about to be inserted
        tmp = int(target_addr.cast(gdb.lookup_type("uint64_t")))
        rip = int(gdb.parse_and_eval("$rip").cast(gdb.lookup_type("uint64_t")))
        if rip >= tmp and rip < tmp + 13:
            self.clean()
            raise gdb.GdbError("The code segment where the trampoline is about to be inserted is being executed.")

        #try to resolve symbol for patch function
        try:
            patch_addr = find_object(self.patch_func).cast(gdb.lookup_type("uint64_t"))
        except:
            self.clean()
            raise gdb.GdbError("Couldn't find patch function symbol.")
        patch_addr_arr = int(patch_addr).to_bytes(8, byteorder = "little")

        #write trampoline
        trampoline = AbsoluteTrampoline()
        trampoline.complete_address(patch_addr_arr)
        #cast target_addr to char *
        trampoline.write_trampoline(target_addr.cast(gdb.lookup_type("char").pointer()))

    def clean(self):
        self.dlclose(self.lib_handle)

class PatchLibStrategy (PatchStrategy):
    def __init__(self, lib_handle: gdb.Value, dlclose: gdb.Value, target_func: str, patch_func: str):
        super().__init__(lib_handle, dlclose, target_func, patch_func)

    def do_patch(self):
        #find target and patch functions
        try:
            target = "'" + self.target_func + "@plt'"
            target = find_object(target)
            patch = find_object(self.patch_func)
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
        patch_arr = int(patch).to_bytes(8, byteorder = "little")

        #write patch function address
        inferior = gdb.selected_inferior()
        inferior.write_memory(addr_got, patch_arr, 8)

    def clean(self):
        pass

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

    def invoke(self, arg, from_tty):
        self.type_dict.clear()
        argv = gdb.string_to_argv(arg)
        if len(argv) != 1:
            raise gdb.GdbError("patch own takes one parameter")

        #find necessary objects
        self.dlopen_addr = find_object("dlopen")
        self.dlclose_addr = find_object("dlclose")
        self.is_patchable()
        self.load_patch_lib(argv[0])
        span = find_patch_section_range(".patch")
        metadata = self.extract_patch_metadata(span[0], span[1])

        for patch in metadata:
            target_func = patch[1]
            patch_func = patch[2]

            if patch[0] == 'O':
                self.strategy = PatchOwnStrategy(self.dlopen_ret, self.dlclose_addr, target_func, patch_func)
            elif patch[0] == 'L':
                self.strategy = PatchLibStrategy(self.dlopen_ret, self.dlclose_addr, target_func, patch_func)
            else:
                raise gdb.GdbError("Patching own and library functions is only supoorted for now.")

            self.strategy.do_patch()

Patch()

import gdb

type_list = ["char", "uint64_t", "int32_t"]

class Patch (gdb.Command):
    "Patch your functions."

    type_dict = {}

    def __init__(self):
        super(Patch, self).__init__("patch", gdb.COMMAND_USER)

    def find_patch_section_range(self) -> tuple[int, int]:
        output = gdb.execute("maintenance info sections -all-objects .patch", False, True)
        index = output.find(".patch")
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

    def extract_patch_metadata(self, section_beg: int, data_length: int) -> tuple[str, str, str]:
        inferior = gdb.selected_inferior()
        items = inferior.read_memory(section_beg, data_length).tobytes().decode().split(":")
        return items[0], items[1], items[2]

    def find_object(self, obj: str) -> gdb.Value:
        try:
            obj_addr = gdb.parse_and_eval(obj)
        except:
            raise gdb.GdbError("Couldn't find " + obj + ".")
        else:
            return obj_addr

    def is_patchable(self):
        try:
            #check if essential types are present in the target process
            for t in type_list:
                self.type_dict[t] = gdb.lookup_type(t)
        except:
            raise gdb.GdbError("Required types were not supported.")
 
    def load_patch_lib(self, path: str):
        dlopen_ret = self.dlopen_addr(path, 2)
        if dlopen_ret == 0:
            raise gdb.GdbError("Couldn't open the patch library.")
       
    def apply_patchown(self):
        target_addr = self.find_object(self.target_func)
        tmp = int(target_addr.cast(self.type_dict["uint64_t"]))
        rip = int(gdb.parse_and_eval("$rip").cast(self.type_dict["uint64_t"]))
        if rip >= tmp and rip < tmp + 13:
            raise gdb.GdbError("The code segment where the trampoline is about to be inserted is being executed.")

        trampoline = bytearray.fromhex("49 bb 00 00 00 00 00 00 00 00 41 ff e3")
        patch_addr = self.find_object(self.patch_func).cast(self.type_dict["uint64_t"])
        patch_addr_arr = int(patch_addr).to_bytes(8, byteorder = "little")

        for i in range(8):
            trampoline[i+2] = patch_addr_arr[i]

        #cast target_addr to char *
        target_addr = target_addr.cast(self.type_dict["char"].pointer())
        inferior = gdb.selected_inferior()
        inferior.write_memory(target_addr, trampoline, 13)

    def apply_patchlib(self):
        #find target and patch functions
        target = "'" + self.target_func + "@plt'"
        target = self.find_object(target)
        patch = self.find_object(self.patch_func)
        patch = patch.cast(gdb.lookup_type("char").pointer())

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

    def invoke(self, arg, from_tty):
        self.type_dict.clear()
        argv = gdb.string_to_argv(arg)
        if len(argv) != 1:
            raise gdb.GdbError("patch own takes three parameters")

        #find necessary objects
        self.dlopen_addr = self.find_object("dlopen")
        self.dlclose_addr = self.find_object("dlclose")
        self.is_patchable()
        self.load_patch_lib(argv[0])
        span = self.find_patch_section_range()
        metadata = self.extract_patch_metadata(span[0], span[1])
        self.target_func = metadata[1]
        self.patch_func = metadata[2]

        if metadata[0] == 'O':
            self.apply_patchown()
        elif metadata[0] == 'L':
            self.apply_patchlib()
        else:
            raise gdb.GdbError("Patching own and library functions is only supoorted for now.")

Patch()

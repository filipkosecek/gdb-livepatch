import gdb

type_list = ["char", "uint64_t", "int32_t"]

class Patch (gdb.Command):
    "Prefix command for live patching functions."

    def __init__(self):
        super(Patch, self).__init__("patch", gdb.COMMAND_SUPPORT, gdb.COMPLETE_NONE, True)


class PatchOwn (gdb.Command):
    "Patch your own functions."

    type_dict = {}

    def __init__(self):
        super(PatchOwn, self).__init__("patch own", gdb.COMMAND_USER)

    def find_object(self, obj: str) -> gdb.Value:
        try:
            obj_addr = gdb.parse_and_eval(obj)
        except:
            raise gdb.GdbError("Couldn't find " + obj + ".")
        else:
            return obj_addr

    def is_patchable(self, target_addr: gdb.Value):
        try:
            #check if essential types are present in the target process
            for t in type_list:
                self.type_dict[t] = gdb.lookup_type(t)

            tmp = int(target_addr.cast(self.type_dict["uint64_t"]))
            rip = int(gdb.parse_and_eval("$rip").cast(self.type_dict["uint64_t"]))
        except:
            raise gdb.GdbError("Required types were not supported.")
        else:
            if rip >= tmp and rip < tmp + 13:
                raise gdb.GdbError("The code segment where the trampoline is about to be inserted is being executed.")

    def load_patch_lib(self, dlopen_addr: gdb.Value, path: str, patch_function: str) -> gdb.Value:
        dlopen_ret = dlopen_addr(path, 2)
        if dlopen_ret == 0:
            raise gdb.GdbError("Couldn't open the patch library.")
        
        try:
            patch_addr = self.find_object(patch_function)
        except:
            dlclose = self.find_object("dlclose")
            dlclose(dlopen_ret)
            raise gdb.GdbError("Couldn't find the patch function.")
        else:
            return patch_addr

    def invoke(self, arg, from_tty):
        self.type_dict.clear()
        argv = gdb.string_to_argv(arg)
        if len(argv) != 3:
            raise gdb.GdbError("patch own takes three parameters")

        #find necessary objects
        dlopen_addr = self.find_object("dlopen")
        target_addr = self.find_object(argv[1])
        trampoline = bytearray.fromhex("49 bb 00 00 00 00 00 00 00 00 41 ff e3")

        self.is_patchable(target_addr)
        patch_addr = self.load_patch_lib(dlopen_addr, argv[0], argv[2])

        patch_addr = patch_addr.cast(self.type_dict["uint64_t"])
        patch_addr_arr = int(patch_addr).to_bytes(8, byteorder = "little")

        for i in range(8):
            trampoline[i+2] = patch_addr_arr[i]

        #cast target_addr to char *
        target_addr = target_addr.cast(self.type_dict["char"].pointer())
        inferior = gdb.selected_inferior()
        inferior.write_memory(target_addr, trampoline, 13)

class PatchLib (gdb.Command):
    "Patch library function."

    def __init__(self):
        super(PatchLib, self).__init__("patch lib", gdb.COMMAND_USER)

    def find_object(self, obj: str) -> gdb.Value:
        try:
            obj_addr = gdb.parse_and_eval(obj)
        except:
            raise gdb.GdbError("Couldn't find " + obj + ".")
        else:
            return obj_addr

    def load_patch_lib(self, dlopen_addr: gdb.Value, path: str, patch_function: str) -> gdb.Value:
        dlopen_ret = dlopen_addr(path, 2)
        if dlopen_ret == 0:
            raise gdb.GdbError("Couldn't open the patch library.")
        try:
            patch_addr = self.find_object(patch_function)
        except:
            dlclose = self.find_object("dlclose")
            dlclose(dlopen_ret)
            raise gdb.GdbError("Couldn't find the patch function.")
        else:
            return patch_addr

    def invoke(self, arg, from_tty):
        argv = gdb.string_to_argv(arg)
        if len(argv) != 3:
            raise gdb.GdbError("patch own takes three parameters")

        inferior = gdb.selected_inferior()

        dlopen = self.find_object("dlopen")
        target = self.find_object("'" + argv[1] + "@plt'")
        patch = self.load_patch_lib(dlopen, argv[0], argv[2])
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
        inferior.write_memory(addr_got, patch_arr, 8)
        

Patch()
PatchOwn()
PatchLib()

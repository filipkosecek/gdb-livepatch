import gdb

class Patch (gdb.Command):
    "Prefix command for live patching functions."

    def __init__(self):
        super(Patch, self).__init__("patch", gdb.COMMAND_SUPPORT, gdb.COMPLETE_NONE, True)


class PatchOwn (gdb.Command):
    "Patch your own function."

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
            tmp = int(target_addr.cast(gdb.lookup_type("uint64_t")))
            rip = int(gdb.parse_and_eval("$rip").cast(gdb.lookup_type("uint64_t")))
        except:
            raise gdb.GdbError("Something went wrong.")
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
        argv = gdb.string_to_argv(arg)
        if len(argv) != 3:
            raise gdb.GdbError("patch own takes three parameters")

        #find necessary objects
        dlopen_addr = self.find_object("dlopen")
        target_addr = self.find_object(argv[1])
        trampoline = bytearray.fromhex("49 bb 00 00 00 00 00 00 00 00 41 ff e3")

        self.is_patchable(target_addr)
        patch_addr = self.load_patch_lib(dlopen_addr, argv[0], argv[2])

        #TODO uint64_t may not be supported
        patch_addr = patch_addr.cast(gdb.lookup_type("uint64_t"))
        patch_addr_arr = int(patch_addr).to_bytes(8, byteorder = "little")

        for i in range(8):
            trampoline[i+2] = patch_addr_arr[i]

        #cast target_addr to char *
        target_addr = target_addr.cast(gdb.lookup_type("char").pointer())
        inferior = gdb.selected_inferior()
        inferior.write_memory(target_addr, trampoline, 13)

Patch()
PatchOwn()

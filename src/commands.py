import gdb

class PatchOwn (gdb.Command):
    "Enables you to patch your own function."

    def __init__(self):
        super(PatchOwn, self).__init__("patchown", gdb.COMMAND_USER)

    def find_object(self, obj: str) -> gdb.Value:
        try:
            obj_addr = gdb.parse_and_eval(obj)
        except:
            raise gdb.GdbError("Couldn't find " + obj + ".")
        else:
            return obj_addr

    def invoke(self, arg, from_tty):
        argv = gdb.string_to_argv(arg)
        if len(argv) != 3:
            raise gdb.GdbError("patch own takes three parameters")

        #find necessary objects
        dlopen_addr = self.find_object("dlopen")
        target_addr = self.find_object(argv[1])
        trampoline = bytearray.fromhex("49 bb 00 00 00 00 00 00 00 00 41 ff e3")

        #check if the code segment where the trampoline is about to be written is not being executed
        tmp = int(target_addr.cast(gdb.lookup_type("uint64_t")))
        rip = int(gdb.parse_and_eval("$rip").cast(gdb.lookup_type("uint64_t")))
        if rip >= tmp and rip < tmp + 13:
            raise gdb.GdbError("The code segment where the trampoline is about to be inserted is being executed.")


        #cast target_addr to char *
        target_addr = target_addr.cast(gdb.lookup_type("char").pointer())


        #dlopen patch library
        dlopen_ret = dlopen_addr("/home/filipkosecek/Documents/patching-tool/examples/inc/patch.so", 2)
        if dlopen_ret == 0:
            raise gdb.GdbError("Couldn't open the patch library.")
        
        try:
            patch_addr = self.find_object(argv[2])
        except:
            dlclose = self.find_object("dlclose")
            dlclose(dlopen_ret)
            raise gdb.GdbError("Couldn't find the patch function.")

        #TODO uint64_t may not be supported
        patch_addr = patch_addr.cast(gdb.lookup_type("uint64_t"))
        patch_addr_arr = int(patch_addr).to_bytes(8, byteorder = "little")

        for i in range(8):
            trampoline[i+2] = patch_addr_arr[i]

        inferior = gdb.selected_inferior()
        inferior.write_memory(target_addr, trampoline, 13)

PatchOwn()

import gdb

class PatchOwn (gdb.Command):
    "Patch your own function"

    def __init__(self):
        super(PatchOwn, self).__init__("patchown", gdb.COMMAND_USER)

    def find_necessary_objects(self, obj: str) -> gdb.Value:
        

    def invoke(self, arg, from_tty):
        argv = gdb.string_to_argv(arg)
        if len(argv) != 3:
            raise gdb.GdbError("patch own takes three parameters")

        try:
            target_addr = gdb.parse_and_eval(argv[1])
        except:
            raise gdb.GdbError("Couldn't find target function.")
        
        target_addr = target_addr.cast(gdb.lookup_type("char").pointer())

        try:
            dlopen_addr = gdb.parse_and_eval("dlopen")
        except:
            raise gdb.GdbError("something went wrong")
        
        dlopen_ret = dlopen_addr("/home/filipkosecek/Documents/patching-tool/examples/inc/patch.so", 2)
        if dlopen_ret == 0:
            raise gdb.GdbError("dlopen failed")

        trampoline = bytearray.fromhex("49 bb 00 00 00 00 00 00 00 00 41 ff e3")
   
        try:
            patch_addr = gdb.parse_and_eval(argv[2])
        except:
            raise gdb.GdbError("Couldn't find patch function.")

        patch_addr = patch_addr.cast(gdb.lookup_type("uint64_t"))
        patch_addr_arr = int(patch_addr).to_bytes(8, byteorder = "little")

        for i in range(8):
            trampoline[i+2] = patch_addr_arr[i]

        inferior = gdb.selected_inferior()
        inferior.write_memory(target_addr, trampoline, 13)
PatchOwn()

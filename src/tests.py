import gdb

def test_add_log_entry():
    le = struct_log_entry(5, 5, "O", 1000, 0, 0, 0)
    backup = struct_patch_backup("test", b'\x79')
    header = read_header("/home/filipkosecek/Documents/gdb-livepatch/examples/inc/patch.so")
#    header.print()
    add_log_entry("/home/filipkosecek/Documents/gdb-livepatch/examples/inc/patch.so", le, backup)
#    read_header("/home/filipkosecek/Documents/gdb-livepatch/examples/inc/patch.so").print()    

def test_read_entry(index: int):
    entry = read_log_entry("/home/filipkosecek/Documents/gdb-livepatch/examples/inc/patch.so", index)
    data = read_log_entry_data("/home/filipkosecek/Documents/gdb-livepatch/examples/inc/patch.so", index)
    print(entry.target_func_ptr)
    print(entry.patch_func_ptr)
    print(entry.patch_type)
    print(entry.timestamp)
    print(entry.patch_data_offset)
    print(entry.path_len)
    print(entry.membackup_len)

    print("")
    print(data.path)
    print(data.membackup)

# Linux process live patching using GDB

The project focuses on Linux process live patching using GNU debugger tool
targeting `x86_64` architecture. It can be used to patch whole functions
of the target process as well tracking and logging changes made.
This extension is also able to revert these changes, i.e. restoring
the original functions.

The extension has its limitations, therefore it is not recommended
to use it for critical software.

## Installation

### GDB

You must have at least GDB 7 installed in your system. GDB is often installed
by default in many Linux distributions. Even if it is not, you can always
install it using a package manager:
```
(Debian) apt install gdb
(Redhat) dnf install gdb
```

### Python

The extension is a python script which can be imported into GDB.
GDB contains embedded python interpreter. The extension is tested
using GDB with python3 interpreter. There are GDB versions that use Python 2 
which is not supported by the extension. To verify what version of python
interpreter you are running, you can visit [this page](https://www.w3resource.com/python-exercises/python-basic-exercise-2.php)
to learn how to do it directly in python interpreter. Any version of Python 3 should be sufficient.
In a GDB session, Python interpreter can be invoked using `python-interactive`.

There are two ways to import the extension script. Firstly, you can launch GDB
with the path (either relative or absolute) to the script as a parameter.
```
gdb -p $pid --command=src/commands.py
```
Alternatively, you can import the script directly from GDB shell using source command:
```
source src/commands.py
```
To automate this task, you can place the script at a fixed path and insert the above
command in your initialization GDB script `.gdbinit` in your home directory.
This will ensure the script will get loaded every time GDB is started.

### Glibc debugging symbols

To make the extension usable, you must install debugging symbols for `glibc`.
These symbols are available in all Linux distributions. They can be installed
via package managers on most Linux distributions.
```
(Debian) apt install libc6-dbg
(Redhat) dnf install glibc-debuginfo
```

## User manual

### Writing a patch library

Patches are represented as shared libraries with declared functions which are to replace
the old ones. The libraries must contain special instructions and metadata declared
in src/patch.h file. In examples/ directory, you can see various examples
which use the defined instructions and metadata definitions and contain
Makefile files for building the patches. Using this building process is strongly advised
so we recommend to make a copy of such a Makefile when writing a patch.
The most important requirements for the building process are:

  - patch libraries must contain debugging symbols
  - patch libraries must be compiled as shared libraries

The extension cannot handle symbol name collisions correctly.
In other words, if you declare a function in your patch library and its name is
already used in the target process, the patching will likely not
work correctly and might crash the process. Symbol names can be
shared across the patch objects as the search scope is limited
to the patch object. For this reason, it is recommended that
replacement functions are named after the functions they are going
to replace with slight modifications, e.g. adding `new_` prefix
to the name of the original function.

### Ataching to a process

To attach to a running process, you have to start with `gdb -p $process_pid`.
Alternatively, you can start GDB with `gdb` and run `attach $process_pid` in GDB shell.

### Executing a patch

To carry out a patch, you have to be attached to the desired process and
run `patch /path/to/your/patchlib`. We recommend to use the absolute path
if the patch library is not in your standard search path. This will invoke
the patching procedure with logging and tracking turned off. If you want
to turn on logging, you have to specify `--log` switch as the second parameter,
i.e.
```
patch /path/to/your/patchlib --log
```
Error handling in the extension is not perfect
so you might encounter errors during the patching. The most common are the following:

  - relative path to the patch library
  - the target process missing both the symbol table and debugging symbols
  - missing glibc debugging symbols
  - missing patch instruction definition, e.g. no definition of the replaced and replacing function
  - typographical errors in replaced or replacing function names

### Printing patch history

When logging was turned on for a patch instance, an entry for it was created and written to the log.
You can print the log with
```
patch-log
```
taking no parameters. It contains patch information, most notably the replaced and the replacing
functions and information whether the patch is active or not. The output of the command
should look something like this:
```
[0] revert
[1] 2023-05-11 20:00:00: old_function -> my/patch/lib:new_function 
[2]* 2023-05-11 20:04:00 old_function -> my/patch/lib2:new_function
```
If the log cannot be found, an error message is printed stating that the log couldn't be found.

### Dumping patch history

It is possible to dump the patch log into a specified file. This might be useful
when you are about to revert some patches and you would like to preserve all changes made.
The usage is as follows:
```
patch-dump /path/to/dest/file
```

### Reapplying patches

It is possible to reapply a patch whose entry is marked in the log.
The `patch-log` outputs a sorted list of marked entries.
You can reapply any patch from the log with `patch-reapply` command
which takes the index of the patch entry in the log. This patch is then reapplied
in case the library containing the replacing function has not already been closed.
A special parameter is 0 which represents patch reversion.

### Reverting patches

You can revert an active patch with `patch-reapply` command with parameter 0.
If no additional parameter is specified, all active patches are reverted.
Otherwise, a list of replaced functions to be restored is specified.
The list can contain either a hex address of the function or its name.
A patch could be reverted like this:
```
patch-reapply 0 old_function
```

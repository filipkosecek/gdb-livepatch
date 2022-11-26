break 12
run

set $i = 0
while $i <= 10
next
p/x x
set $i += 1
end

#path hardcoded for now
set $PATH = "/home/filipkosecek/Documents/patching-tool/example/patch.so"

#TODO check return value of dlopen
set $DLOPEN_RET = dlopen($PATH, 2)
set $PATCH_ADDR = (char *)&patch_function
set $TARGET_ADDR = (char *)&target_function
set $TRAMPOLINE = (char [13]) {0x49, 0xBB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x41, 0xFF, 0xE3}

#convert to array of bytes
set $PATCH_ADDR_ARR = (char[8])$PATCH_ADDR

#copy address of dlopened object to trampoline
set $i = 0
while $i <= 7
set $TRAMPOLINE[$i+2] = $PATCH_ADDR_ARR[$i]
set $i += 1
end

#write trampoline into the target function
set $i = 0
while $i <= 12
set $TARGET_ADDR[$i] = $TRAMPOLINE[$i]
set $i += 1
end


#test trampoline
#set $i = 0
#while $i < 13
#p/x $TRAMPOLINE[$i]
#set $i += 1
#end

#test target function
#set $i = 0
#while $i < 18
#p/x $TARGET_ADDR[$i]
#set $i += 1
#end

#test patch object
#set $i = 0
#while $i < 29
#p/x $PATCH_ADDR[$i]
#set $i += 1
#end

continue
#detach

#overall test
#set $i = 0
#while $i <= 19
#p/x x
#next
#set $i += 1
#end

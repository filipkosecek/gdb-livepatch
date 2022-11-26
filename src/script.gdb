#load patch module
define loadpatch
	if $argc != 1
		echo "Something went wrong!"
		detach
	end

	set $DLOPEN_RET = dlopen($arg0, 2)
	if $DLOPEN_RET == 0
		echo "Couldn't find dlopen function."
		detach
	end
end


define writepatch
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
end


define execpatch
	if $argc != 2
		echo "You must specify path to your patch library and the point where your program stops execution before applying the patch!"
	else
		break $arg1
		continue
		clear $arg1
		loadpatch $arg0
		writepatch
	end
end

#main
#execpatch "/home/filipkosecek/Documents/patching-tool/example/patch.so" 12

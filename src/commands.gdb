#load patch module
define load-patch
	if $argc != 1
		echo "Something went wrong!"
	end

	#TODO check if dlopen is loaded
	set $DLOPEN_ADDR = &dlopen

	set $DLOPEN_RET = dlopen($arg0, 2)
	if $DLOPEN_RET == 0
		echo "Couldn't open patch library."
	end
end

#write trampoline to replace function $arg0 with $arg1
define write-trampoline
	if $argc != 2
		echo "You have to specify target and replace functions!"
	end

	set $PATCH_ADDR = (char *)&$arg1
	set $TARGET_ADDR = (char *)&$arg0
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


define exec-patch-own
	if $argc != 4
		echo "Wrong number of arguments! The list goes: path to patch library, line where the program stops execution before applying the patch, name of the function to be replaced, replace function!"
	else
		break $arg1
		continue
		clear $arg1
		load-patch $arg0
		write-trampoline $arg2 $arg3
	end
end

define exec-patch-lib
	if $argc != 1
		echo "You must specify path to your patch library and the point where your program stops execution before applying the patch!"
	else
		load-patch $arg0
		
		#find plt record, hardcoded for now
		set $PLT_RECORD = (char *) & 'puts@plt'
		set $RELATIVE_OFFSET = $PLT_RECORD + 2
		set $RELATIVE_OFFSET = (int32_t *) $RELATIVE_OFFSET
	
		set $NEXT_INSTRUCTION = $PLT_RECORD + 6
		set $OFFSET = $NEXT_INSTRUCTION + *$RELATIVE_OFFSET
		set $OFFSET = (uint64_t *) $OFFSET
		set *$OFFSET = (char *) &my_puts
	end
end

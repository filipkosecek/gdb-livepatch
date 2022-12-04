define patch-own
	dont-repeat
	if $argc == 3
		#initialize variables
		set $DLOPEN_ADDR = -1
		set $PATCH_ADDR = -1
		set $TARGET_ADDR = -1

		#check if essential functions are present
		set $DLOPEN_ADDR = &dlopen
		set $TARGET_ADDR = (char *) &$arg1
		
		if ($TARGET_ADDR != -1 && $DLOPEN_ADDR != -1)

			#check if the code segment where the trampoline is about to be placed is not being executed
			if ($rip < $TARGET_ADDR || $rip >= $TARGET_ADDR + 13)

				#dlopen the patch library
				set $DLOPEN_RET = dlopen($arg0, 2)
				if $DLOPEN_RET != 0
					set $TRAMPOLINE = (char [13]) {0x49, 0xBB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x41, 0xFF, 0xE3}

					set $PATCH_ADDR = (char *) &$arg2

					#TODO dlclose if the specified function is not listed in the patch library
					#we want to avoid crash
					if $PATCH_ADDR == -1
						echo "Couldn't find the patch function in the patch library."
						set $DLCLOSE_RET = dlclose($DLOPEN_RET)
					else
					
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
				else
					echo "Couldn't open the patch library."
				end
			else
				echo "Control flow is just in the point where the trampoline is about to be written."
			end
		else
			echo "Couldn't find target function or dlopen."
		end
	else
		echo "You have to specify target and patch functions."
	end
end

#TODO parametrize target and patch functions
define patch-lib
	dont-repeat
	if $argc == 3
		set $PLT_RECORD = -1
		set $DLOPEN_ADDR = -1

		#find plt record, hardcoded for now
		set $PLT_RECORD = (char *) & 'puts@plt'
		set $DLOPEN_ADDR = &dlopen

		if ($DLOPEN_ADDR != -1 && $PLT_RECORD != -1)
			if (dlopen($arg0, 2) != 0)

				#extract relative offset of got.plt record from indirect call instruction
				set $RELATIVE_OFFSET = $PLT_RECORD + 2
				set $RELATIVE_OFFSET = (int32_t *) $RELATIVE_OFFSET

				#calculate relative offset of 
				set $NEXT_INSTRUCTION = $PLT_RECORD + 6
				set $OFFSET = $NEXT_INSTRUCTION + *$RELATIVE_OFFSET
				set $OFFSET = (uint64_t *) $OFFSET
				set *$OFFSET = (char *) &my_puts
			else
				echo "Couldn't open the patch library."
			end
		else
			echo "Couldn't find dlopen or record for target function."
		end
	else
		echo "Wrong number of arguments."
	end
end

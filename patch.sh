# This script reduces the downtime of patch application
# Invokes GDB and performs the specified operation

#!/bin/bash

# check arg count
if [[ "$#" -lt 2 ]]; then
	echo "You must specify pid and operation to be performed." 1<&2
	exit 1
fi

#check if the process exists
if [[ -z $(ps -e | grep "$1") ]]; then
	echo "Invalid pid." 1<&2
	exit 1
fi

case $2 in
	# patch commands
	patch)
		# no logging
		if [[ "$#" -eq 3 ]]; then
			COMMANDS="patch $3\n"
		#logging
		elif [[ "$#" -eq 4 ]]; then
			#check if the patch library exists
			if [[ ! -f "$3" ]]; then
				echo "The patch library does not exist." 1<&2
				exit 1
			fi
			if [[ "$4" != "--log" ]]; then
				echo "Enter \"--log\" to turn on logging." 1<&2
				exit 1
			fi
			COMMANDS="patch $3 --log\n"
		else
			echo "Enter pid and path to patch library and optionally turn on logging." 1<&2
			exit 1
		fi
		;;

	patch-log)
		if [[ "$#" -ne 2 ]]; then
			echo "Enter pid and \"patch-log\" command." 1<&2
			exit 1
		fi
		COMMANDS="patch-log\n"
		;;

	patch-reapply)
		if [[ "$#" -lt 3 ]]; then
			echo "Enter pid and \"patch-reapply\" and its arguments." 1<&2
			exit 1
		fi

		# check if argument is a number
		re='^[0-9]+$'
		if ! [[ $3 =~ $re ]] ; then
			echo "\"patch-reapply\" takes a number as an argument" 1<&2
			exit 1
		fi
		# append optional parameters
		COMMANDS=$(echo "patch-reapply $3")
		for i in "${@:4}"; do
			COMMANDS="${COMMANDS} $i"
		done
		COMMANDS="${COMMANDS}\n"
		;;

	*)
		echo "Unknown command. Use one of the following: {\"patch\", \"patch-log\", \"patch-reapply\"}." 1<&2
		exit 1
		;;
esac

# path to python script
PYTHON_SCRIPT_PATH="src/commands.py"

# invoke GDB
echo -en $COMMANDS | gdb -p "$1" --command="${PYTHON_SCRIPT_PATH}"

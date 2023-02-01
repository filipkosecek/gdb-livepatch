#!/bin/bash

if [[ $# -ne 2 ]]; then
	echo "Enter the type of operation, pid and path to patch libary." 1<&2
	exit 1
fi

#check if pid is valid
if [[ -z $( ps -e | grep $1 ) ]]; then
	echo "Pid is not valid." 1<&2
	exit 1
fi

#create command file for gdb
COMMANDS=".tmp.gdb"
echo "source $( pwd )/src/commands.py" > $COMMANDS
echo "patch $2" >> $COMMANDS
echo "detach" >> $COMMANDS

gdb -p $1 --batch --command=$COMMANDS

rm $COMMANDS

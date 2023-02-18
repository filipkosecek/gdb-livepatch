#!/bin/bash

if [[ "$#" -ne 3 ]]; then
	echo "Enter the type of operation, pid and path to patch libary." 1<&2
	exit 1
fi

if [[ $3 != "T" && $3 != "R" ]]; then
	echo "Either trigger or revert." 1<&2
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
echo "patch $2 $3" >> $COMMANDS
echo "detach" >> $COMMANDS

gdb -p $1 --command=$COMMANDS

rm $COMMANDS
echo $1 | xargs kill

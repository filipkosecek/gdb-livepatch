#!/bin/bash

#TODO handle errors

SECTION=".patch"
DELIMITER=";"
OUTFILE="${SECTION}-dump.bin"

if [[ $# -ne 3 ]]; then
	echo "Enter the type of operation, pid and path to patch libary." 1<&2
	exit 1
fi

if [[ $1 != "apply" ]]; then
	echo "Only patch application is for now supported." 1<&2
	exit 1
fi

#check if pid is valid
if [[ -z $( ps -e | grep $2 ) ]]; then
	echo "Pid is not valid." 1<&2
	exit 1
fi

#check if there is a patch section in patch library
objdump -s -j $SECTION $3 > /dev/null
if [[ $? -ne 0 ]]; then
	echo "Could't find .patch section in the patch library." 1<&2
	exit 1
fi

#extract data from .patch section
objcopy --dump-section $SECTION=$OUTFILE $3
META=$( cat $OUTFILE )
rm $OUTFILE
if [[ -z $META ]];then
	echo "Invalid metadata in .patch section." 1<&2
	exit 1
fi

#TODO check if characters are printable
#extract metadata
TYPE=$( echo $META | cut -d ':' -f 1 )
OLD=$( echo $META | cut -d ':' -f 2 )
NEW=$( echo $META | cut -d ':' -f 3 )

if [[ $TYPE != "O" && $TYPE != "L" ]] || [[ -z $OLD || -z $NEW ]];then
	echo "Invalid metadata format." 1<&2
	exit 1
fi

#create command file for gdb
COMMANDS=".tmp.gdb"
echo "source $( pwd )/src/commands.py" >> $COMMANDS
if [[ $TYPE == "O" ]]; then
	echo -n "patch own " >> $COMMANDS
else
	echo -n "patch lib " >> $COMMANDS
fi
echo "\"$3\" ${OLD} ${NEW}" >> $COMMANDS
echo "detach" >> $COMMANDS

gdb -p $2 --batch --command=$COMMANDS

rm $COMMANDS

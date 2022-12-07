#!/bin/bash

PATH_OWN="/home/filipkosecek/Documents/patching-tool/examples/inc/"
PATH_LIB="/home/filipkosecek/Documents/patching-tool/examples/hello/"

make -C $PATH_OWN all
make -C $PATH_LIB all

./examples/inc/patch_target & disown

target_pid=$( ps -e | grep "patch_target" | awk '{ print $1 }' )
echo "The target's pid is: ${target_pid}."

gdb -p "${target_pid}" --command=src/commands.py

echo $target_pid | xargs kill

./examples/hello/test & disown
sleep 2;

target_pid=$( ps -e | grep "test" | awk '{ print $1 }' )

echo "The target's pid is: ${target_pid}."

gdb -p $target_pid --command=src/commands.py

echo $target_pid | xargs kill

make -C $PATH_OWN clean
make -C $PATH_LIB clean

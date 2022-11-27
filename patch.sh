#!/bin/bash

PATH="/home/filipkosecek/Documents/patching-tool/examples/inc/"
make -C $PATH all
./example/patch_target & disown

target_pid=$( ps -e | grep "patch_target" | awk '{ print $1 }' )
echo "The target's pid is: ${target_pid}"

gdb -p $target_pid --command=src/script.gdb

echo $target_pid | xargs kill "patch_target"
make -C $PATH clean

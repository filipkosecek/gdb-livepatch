#!/bin/bash

make -C /home/filipkosecek/Documents/testing/src/ all
./src/patch_target & disown

target_pid=$( ps -e | grep "patch_target" | awk '{ print $1 }' )
echo "The target's pid is: ${target_pid}"

gdb -p "$target_pid" --batch --command=script.gdb

kill $targtet_pid
make -C /home/filipkosecek/Documents/testing/src/ clean

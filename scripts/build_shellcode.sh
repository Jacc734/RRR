#!/bin/bash

echo "[+] Building binary..."

source=$1
source_o=`echo ${source/.S/.o}`
executable=`echo ${source/.S/}`
nasm -f elf $source
ld -o $executable $source_o
sudo chmod 744 $executable

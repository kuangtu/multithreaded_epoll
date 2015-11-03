#!/bin/bash
echo "Usage: Arg1: Server ID Arg2: File Size Arg3: Number of files to create\n"
echo "Arg4: Directory to create files in\n"
count=$3
counter=1
while [ $counter -le $count ]; do
	dd if=/dev/urandom of=$4/sample$1$counter.txt bs=$2 count=1
	let counter=counter+1
done

echo "$3 files of size $2 created for Server $1"

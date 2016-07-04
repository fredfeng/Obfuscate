#!/bin/bash

#for f in /home/yufeng/research/benchmark/malware/FakeInstaller/*; do
#  echo "Analyzing..... $f"
#  ant main -Dapk=$f -Dsdk=/home/yufeng/lib/android-sdk-linux/platforms/ 
#done

#find /home/yufeng/research/benchmark/malware/ -iname '*.apk' | while read line; do
#    echo "Analyzing..... $line"
#    ant main -Dapk=$line -Dsdk=/home/yufeng/lib/android-sdk-linux/platforms/ 
#done


for i in $(find /home/yufeng/research/benchmark/malware/ -iname '*.apk' ); 
do
    echo "Analyzing..... $i"
    ant main -Dapk=$i -Dsdk=/home/yufeng/lib/android-sdk-linux/platforms/ 
done

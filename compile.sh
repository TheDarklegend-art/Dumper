#!/bin/bash
echo "Compiling Eight Ball Pool Dumper..."
clang++ -std=c++11 -Wall -O2 -D__ANDROID__ dumper.cpp -o dumper -llog -landroid
echo "Compilation complete! Run with: ./dumper"
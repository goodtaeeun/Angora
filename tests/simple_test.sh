#!/bin/sh
set -x


## Set basic paths
export PATH=/fuzzer/Angora/clang+llvm/bin:$PATH
export PATH=/fuzzer/Angora/clang+llvm/lib:$PATH
export PATH=/root/go/bin:$PATH
export ANGORA_TAINT_RULE_LIST=/fuzzer/Angora/bin/rules/zlib_abilist.txt 


## Provide test directory as argument, i.e., pointer_arith
## Make sure that there is 
## 1) a c code with identical name,
## 2) a file named "args" which will be given to the program (either by command line argument, or by stdin)
## 3) a file named "target" which contains the line information to extract the taint information (e.g., a.c:10)
export target=$1
export ANGORA_TAINT_TARGET=/fuzzer/Angora/tests/$target/target
echo $ANGORA_TAINT_TARGET

## Compile the target program
gclang $target/$target.c -g -o naive_bin

## Extract the bitcode
get-bc naive_bin

## Recompile the bitcode with Angora
../bin/angora-clang naive_bin.bc -o tainted_bin

## Run the program with Angora
./tainted_bin

## Check the output
cat taint.out
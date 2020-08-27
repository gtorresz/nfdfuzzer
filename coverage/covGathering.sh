#!/bin/bash
for filename in ../FuzzerTrace/*;
do
	sudo LLVM_PROFILE_FILE="rawData/$(basename "$filename").profraw" ./../NFD/build/daemon/fuzzer/visualizer $filename 
done
llvm-profdata merge -sparse rawData/*.profraw -o data.profdata
llvm-cov report ./../NFD/build/daemon/fuzzer/visualizer -instr-profile=data.profdata

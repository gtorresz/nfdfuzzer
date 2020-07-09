configuration command for NFD
CXX=clang++ ./waf configure --with-sanitizer=address --with-coverage --debug --fuzzing

configuration command for ndn-cxx
CXX=clang++ ./waf configure --with-sanitizer=address --with-coverage --debug 

Steps to gather coverage, can also, and perferably, be done with script provided within coverage folder
sudo LLVM_PROFILE_FILE=<dataFileName> ./build/daemon/visualizer <packetTraceFile>
llvm-profdata merge -sparse default.profraw -o default.profdata
llvm-cov report ./build/daemon/visualizer -instr-profile=foo.profdata

configuration command for NFD
CXX=clang++ ./waf configure --with-sanitizer=address --with-coverage --debug --fuzzing

configuration command for ndn-cxx
CXX=clang++ ./waf configure --with-sanitizer=address --with-coverage --debug 

Steps to gather coverage, can also, and perferably, be done with script provided within coverage folder
sudo LLVM_PROFILE_FILE=<dataFileName> ./build/daemon/visualizer <packetTraceFile>
llvm-profdata merge -sparse default.profraw -o default.profdata
llvm-cov report ./build/daemon/visualizer -instr-profile=foo.profdata

install cmake
sudo apt install cmake

install flatbuffer
choice "folder for installation"
cd "folder for installation"
git clone https://github.com/google/flatbuffers.git
cd flatbuffers
CC=/usr/bin/clang CXX=/usr/bin/clang++ cmake -G "Unix Makefiles"
make
sudo ln -s /full-path-to-flatbuffer/flatbuffers/flatc /usr/local/bin/flatc
chmod +x /full-path-to-flatbuffer/flatbuffers/flatc
run in any place as "flatc"



./fuzzer MY_CORPUS -max_len=8093 -DCUSTOM_MUTATOR

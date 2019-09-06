Both fuzzer.cpp and the visulizer.cpp should be placed in NFD's daemon folder. Ex: daemon/fuzzer.cpp
The wscript should replace the wscript in the main directory of NFD. 
The mutator.hpp file is currently set up to be in the ndn-cxx directory under the ndn-cxx sub-folder. It can really be placed anywhere though as long as the refernce to it in fuzzer.cpp is updated.  
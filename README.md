# NFDFuzz - A Stateful Structure-Aware Fuzzer for Named Data Networking

## Overview

NFDFuzz is a fuzzer for NFD which is capable of prdocuing random NDN packets that are valid enough to pass the parser of NFD yet still able to find code cases in NFD's codebase. 

## Setting up NFDFuzz 
Prerequisites for running and updating NFDFuzz
- [LLVM](https://github.com/llvm/llvm-project) should be installed from either linux distribution or from source. From source it may be easier to install NFDFuzz's LLVM patch needed for NFDFuzz.
- Cmake should be installed with 
	sudo apt install cmake
- Google's [Flatbuffers](https://github.com/google/flatbuffers.git) should be installed, as of now there is not a linux distrubtion at least to my knowledge so it must be installed from source. After installing flatbuffers run the following commands to setup flatc to be run anywhere
    - sudo ln -s /full-path-to-flatbuffer/flatbuffers/flatc /usr/local/bin/flatc
    - chmod +x /full-path-to-flatbuffer/flatbuffers/flatc
	
We must also configure both NFD and ndn-cxx correctly to allow the fuzzer to run correctly.

For NFD run 
- CXX=clang++ ./waf configure --with-sanitizer=address --with-coverage --debug --fuzzing

For ndn-cxx run
- CXX=clang++ ./waf configure --with-sanitizer=address --with-coverage --debug 

## Running NFDFuzz and gathering coverage
A script, runFuzzer.sh, is provided so that the fuzzer may be run easily. Inside of the script is a command to run the fuzzer, this can modifed if you want to change the corpus or adjust the max input size. 

Inside of the coverage folder there is a script, covGathering.sh, available for gathering coverage data from preivously run instances of the fuzzer. 

## Altering NFDFuzz
Inputs are in flatbuffer format, the descriptons for these formats are stored in, "NFD/daemon/fuzzer/util". You can make changes to the existing .fbs files or add your own. Whenever this is done run "flatc -cpp \<filename\>.fbs inside of this folder to generate the appropriate header files for the fuzzer. If new .fbs files where created the newly generated header files should be included inside of nfd\_runner.hpp located inside the fuzzer folder of NFD.

Other modifications can be done inside the mutator functions or the fuzzer.cpp file, which are all located inside the fuzzer folder. 

## Modifications done to ndn-cxx and NFD
There were only additions made to ndn-cxx. The files that were added are meant to allow NFD to be as deterministic as possible, to this end a seeded-random hpp and cpp file were created, which are similar to the regular random file provide by ndn-cxx except they are meant to be seeded. Another file fuzzer-seed.hpp is created to allow for the sharing of the seed generated by the fuzzer. 

All of the additons to NFD reside inside the fuzzer folder, with the exception of the configuration option for the fuzzer which was added in the .waf-tools folder. There where modifications done to wscript and other files that use a random function. These files where modified so that there use of the base ndn-cxx random files are replaced with the seeded-random files if the approipriate flags where added during configuration. 

The files modified in NFD are:
- wscript
- daemon/fw/asf-probing-module.cpp
- daemon/fw/asf-probing-module.cpp
- daemon/fw/random-strategy.cpp
- daemon/rib/readvertise/readvertise.cpp

# Notes
Currently the wscript is set up to look for the libfuzzer library inside of the nfdfuzzer folder, this needs to be changed. 

LLVM is currently installed both from distribution and from source. This is due to two different libraries for libfuzzer being used, one is for linking without a main, and enabling coverage, and the other is for linking the main function provided by libfuzzer to the fuzzer.
The patch can be applied to the llvm source and then the script to make the library can be found at llvm-project/compiler-rt/lib/fuzzer/build.sh.

If there is some trouble getting the correct cmake version follow these steps :
   - sudo apt-get update
   - sudo apt-get install apt-transport-https ca-certificates gnupg \ software-properties-common wget
   - wget -qO - https://apt.kitware.com/keys/kitware-archive-latest.asc | sudo apt-key add -

For Ubuntu Bionic Beaver (18.04):

   - sudo apt-add-repository 'deb https://apt.kitware.com/ubuntu/ bionic main'
   - sudo apt-get update

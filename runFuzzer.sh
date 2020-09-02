#!/bin/bash
mkdir MY_CORPUS
mkdir FuzzerTrace
sudo ./NFD/build/daemon/fuzzer/fuzzer MY_CORPUS -max_len=16184 

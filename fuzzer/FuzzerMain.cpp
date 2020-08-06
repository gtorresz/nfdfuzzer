//===- FuzzerMain.cpp - main() function and flags -------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
// main() and flags.
//===----------------------------------------------------------------------===//

#include "FuzzerDefs.h"
#include <iostream> 
#include <thread>
#include <unistd.h>
#include <sys/select.h>
#include <sys/time.h>
extern "C" {
// This function should be defined by the user.
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
}  // extern "C"

extern "C" {
  void SetUp();
 }  // extern "C"

ATTRIBUTE_INTERFACE int main(int argc, char **argv) {
    std::thread t1(SetUp);
    struct timeval t;
    t.tv_sec = 10;
    t.tv_usec = 500000;
    select(0, NULL, NULL, NULL, &t);
  return fuzzer::FuzzerDriver(&argc, &argv, LLVMFuzzerTestOneInput);
}

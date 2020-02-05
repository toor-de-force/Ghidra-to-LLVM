// Copyright 2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

int main() {
  path_start();
  int n = SMALL_POSITIVE_RAND;
  n++;
  volatile int t = n; // volatile to prevent optimization of nongoal
  if (t == 0) {
    path_nongoal();
  }
  path_goal();
}

#!/bin/bash -eu
# SPDX-License-Identifier: Apache-2.0
#
# ClusterFuzzLite / OSS-Fuzz build: compile every cargo-fuzz target in fuzz/ with the sanitizer
# flags the builder sets, copy the binaries to $OUT, and ship each target's hand-picked seeds
# (fuzz/seeds/<target>) as its seed corpus.

cd "$SRC/light-waf/fuzz"
cargo fuzz build -O

release="target/x86_64-unknown-linux-gnu/release"
for target in $(cargo fuzz list); do
  cp "$release/$target" "$OUT/"
  if [ -d "seeds/$target" ]; then
    (cd "seeds/$target" && zip -q -r "$OUT/${target}_seed_corpus.zip" .)
  fi
done

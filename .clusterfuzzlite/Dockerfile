# SPDX-License-Identifier: Apache-2.0
# ClusterFuzzLite build image: the OSS-Fuzz Rust builder (nightly toolchain, cargo-fuzz, libFuzzer),
# pinned by digest, with this repository copied in. build.sh compiles the cargo-fuzz targets in fuzz/.
FROM gcr.io/oss-fuzz-base/base-builder-rust:v1@sha256:3428d0a90b1e7efbe2ba947bd1d0c9a70594986b4b6553804547f1fb24cfc92f
COPY . $SRC/light-waf
WORKDIR $SRC/light-waf
COPY .clusterfuzzlite/build.sh $SRC/

# Run every cargo-fuzz target for 20 s (Linux/macOS, nightly). CI does this with ClusterFuzzLite.
for t in $(cargo fuzz list); do
  echo "== $t =="
  seeds=""
  [ -d "fuzz/seeds/$t" ] && seeds="fuzz/seeds/$t"
  cargo fuzz run "$t" $seeds -- -max_total_time=20 -timeout=5 || break
done

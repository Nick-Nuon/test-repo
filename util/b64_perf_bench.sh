#!/bin/bash
set -e

LIB="./apps/openssl"
DATA="./util/benchmark_data"
OUT_DIR="$DATA/perf_results"
mkdir -p "$OUT_DIR"

TS=$(date +%Y%m%d_%H%M%S)

# Full LD path set inside the shell for perf
run_perf() {
  label="$1"
  body="$2"
  echo "🔥 Running perf for: $label"
  perf record -o "$OUT_DIR/perf_${label}_${TS}.data" -e cycles,cache-misses --call-graph dwarf \
    bash -c 'export LD_LIBRARY_PATH="$(pwd):$(pwd)/lib"; '"$body"' > /dev/null'
  perf report --stdio -i "$OUT_DIR/perf_${label}_${TS}.data" > "$OUT_DIR/perf_${label}_${TS}.txt"
  echo "📊 Saved to: $OUT_DIR/perf_${label}_${TS}.txt"
  echo ""
}

### 🔽 Begin Benchmarks

echo "📏 Benchmark: Single file (lena_color_512.jpg)"
run_perf "lena_color" \
  "$LIB enc -base64 -A -in $DATA/Mula_img/lena_color_512.jpg"

echo "📦 Benchmark: All files in Mula_img"
run_perf "Mula_img" \
  'for f in ./util/benchmark_data/Mula_img/*; do [ -f "$f" ] && ./apps/openssl enc -base64 -A -in "$f"; done'

echo "📨 Benchmark: All files in email_bin"
run_perf "email_bin" \
  'for f in ./util/benchmark_data/email_bin/*; do [ -f "$f" ] && ./apps/openssl enc -base64 -A -in "$f"; done'

echo "📘 Benchmark: Pride and Prejudice"
run_perf "pride" \
  'for f in ./util/benchmark_data/one_big_file/*; do [ -f "$f" ] && ./apps/openssl enc -base64 -A -in "$f"; done'

echo "✅ Perf profiling complete at $(date)"

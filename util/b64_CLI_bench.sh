#!/bin/bash
set -e

# Check if the OS is Linux
if [[ "$(uname -s)" != "Linux" ]]; then
    echo "❌ This script must be run on Linux. Detected: $(uname -s)"
    exit 1
fi

echo "🛠️  Configuring and building OpenSSL with gcc and -march=native -mtune=native..."

# # === Setup log file ===
LOGFILE="./benchmark_results/base64_benchmark_CLI_gcc_$(date +'%Y-%m-%d_%H-%M-%S').log"
exec > >(tee -a "$LOGFILE") 2>&1

echo "📝 Logging to $LOGFILE"
echo "Benchmark started at $(date)"
echo "========================================================"

# # === Configure and build OpenSSL with gcc + native CPU tuning ===

# ./config linux-x86_64-gcc -march=native -mtune=native
./config -march=native -mtune=native
make clean
echo "🛠️  Building OpenSSL quietly..."
if ! make -j"$(nproc)" > /dev/null 2>&1; then
    echo "❌ Build failed!"
    exit 1
fi

# # === Build standalone benchmark binary ===
# echo "🧪 Compiling base64_encoding_benchmark.c with GCC..."
gcc -O3 -mavx2 -I./include \
    ./util/base64_encoding_benchmark.c \
    ./crypto/evp/encode.c \
    ./crypto/evp/enc_b64_scalar.c \
    ./crypto/evp/enc_b64_avx2.c \
    -o ./util/perf_basic -lcrypto

  run_hyperfine_benchmark() {
    local label="$1"
    local dir="$2"
    echo "$label"
    LD_LIBRARY_PATH=$(pwd):$(pwd)/lib \
    hyperfine --warmup 500 --min-runs 2000 \
      "for f in $dir/*; do [ -f \"\$f\" ] && ./apps/openssl enc -base64 $mode_flag -in \"\$f\" > /dev/null; done"
  }


run_benchmarks() {
  local mode_flag="$1"
  local mode_name="$2"

  echo "============== $mode_name ============================="

  echo "📏 Benchmark: Single file (lena_color_512.jpg)"
  LD_LIBRARY_PATH=$(pwd):$(pwd)/lib \
  hyperfine --warmup 1000 --min-runs 4000 \
    "./apps/openssl enc -base64 $mode_flag -in ./util/benchmark_data/Mula_img/lena_color_512.jpg > /dev/null"


  run_hyperfine_benchmark "📦 Benchmark: All files in Mula_img" "./util/benchmark_data/Mula_img"
  run_hyperfine_benchmark "📨 Benchmark: All files in email_bin" "./util/benchmark_data/email_bin"
  run_hyperfine_benchmark "📨 Benchmark: Pride and prejudice" "./util/benchmark_data/one_big_file"
}

run_benchmarks "-A" "DISABLE NEWLINES MODE CLI"
run_benchmarks "" "PEM MODE CLI"



echo "✅ Benchmarks complete at $(date)"
echo "Results logged to: $LOGFILE"

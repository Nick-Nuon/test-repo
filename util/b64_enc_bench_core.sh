#!/bin/bash
set -e

# Check if the OS is Linux
if [[ "$(uname -s)" != "Linux" ]]; then
    echo "❌ This script must be run on Linux. Detected: $(uname -s)"
    exit 1
fi

echo "🛠️  Configuring and building OpenSSL with GCC and -march=native -mtune=native..."

make clean
# # === Setup log file ===
LOGFILE="util/benchmark_results/base64_benchmark_gcc_$(date +'%Y-%m-%d_%H-%M-%S').log"
exec > >(tee -a "$LOGFILE") 2>&1

echo "📝 Logging to $LOGFILE"
echo "Benchmark started at $(date)"
echo "========================================================"

# # === Configure and build OpenSSL with GCC + native CPU tuning ===
./config -march=native -mtune=native
echo "🛠️  Building OpenSSL quietly..."
if ! make -j"$(nproc)" > /dev/null 2>&1; then
    echo "❌ Build failed!"
    exit 1
fi

# # === Build standalone benchmark binary ===
echo "🧪 Compiling base64_encoding_benchmark.c with GCC..."
gcc -O3 -mavx2 -I./include \
    ./util/base64_encoding_benchmark.c \
    ./crypto/evp/encode.c \
    ./crypto/evp/enc_b64_scalar.c \
    ./crypto/evp/enc_b64_avx2.c \
    -o ./util/perf_basic -lcrypto

# # === Setup log file ===
LOGFILE="./benchmark_results/base64_benchmark_gcc_$(date +'%Y-%m-%d_%H-%M-%S').log"
exec > >(tee -a "$LOGFILE") 2>&1

echo "📝 Logging to $LOGFILE"

# # === Run benchmark binary on Enron email files ===
echo "📂 Benchmark: Enron email files"
sudo ./util/perf_basic util/benchmark_data/email_bin
echo " "

# # === Run benchmark binary on Mula image files ===
echo "🖼️  Benchmark: Mula JPG files"
sudo ./util/perf_basic util/benchmark_data/Mula_img
echo " "

make clean
echo "🛠️  Configuring and building OpenSSL with gcc and -march=native -mtune=native..."

echo "✅ Benchmarks complete at $(date)"
echo "Results logged to: $LOGFILE"
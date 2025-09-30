
#include <string.h>

#if (defined(__x86_64__) || defined(_M_AMD64)) && !defined(_M_ARM64EC)

    #include <immintrin.h>
    #include <openssl/evp.h>
    #include <stddef.h>
    #include <stdint.h>
    #include "enc_b64_scalar.h"

    #include "internal/cryptlib.h"
    #include "crypto/evp.h"
    #include "evp_local.h"



     //example : when index = 0 (lowercase class).
    // For input in [26..51], you want ASCII = 'a' (97) + (input-26).
    // That equals input + ('a' - 26).
    // Example: input=26 → 26+('a'-26)=97='a'; input=27→98='b'.
    // static __m256i lookup_pshufb_std(__m256i input, int is_srp) {
    // }

    typedef __m256i (*lookup_fn)(__m256i v);
    
    static __m256i lookup_pshufb_std(__m256i input) {
        __m256i result = _mm256_subs_epu8(input, _mm256_set1_epi8(51));
        const __m256i less = _mm256_cmpgt_epi8(_mm256_set1_epi8(26), input);
        result = _mm256_or_si256(result, _mm256_and_si256(less, _mm256_set1_epi8(13)));
        
        __m256i shift_LUT = _mm256_setr_epi8(
            'a' - 26, '0' - 52, '0' - 52, '0' - 52, '0' - 52, '0' - 52, '0' - 52,
            '0' - 52, '0' - 52, '0' - 52, '0' - 52, '+' - 62, '/' - 63, 'A', 0, 0,
            'a' - 26, '0' - 52, '0' - 52, '0' - 52, '0' - 52, '0' - 52, '0' - 52,
            '0' - 52, '0' - 52, '0' - 52, '0' - 52, '+' - 62, '/' - 63, 'A', 0, 0);

        result = _mm256_shuffle_epi8(shift_LUT, result);
        return _mm256_add_epi8(result, input);
    }


    


// // Normal Base64 alphabet
// static const unsigned char data_bin2ascii[65] =
//     "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// /* SRP uses a different base64 alphabet */
// static const unsigned char srpdata_bin2ascii[65] =
//     "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz./";

// Map 6-bit values (0..63) into ASCII Base64 chars using AVX2, branchless.
// This assumes the input vector contains only values in the range [0..63].
//
// Normal Base64 alphabet:
//   0..25  → 'A'..'Z'
//   26..51 → 'a'..'z'
//   52..61 → '0'..'9'
//   62     → '+'
//   63     → '/'

// SRP Base64 alphabet:
//   0..9   → '0'..'9'
//   10..35 → 'A'..'Z'
//   36..61 → 'a'..'z'
//   62     → '.'
//   63     → '/'

static __m256i lookup_pshufb_model(__m256i input) {
    // this targets alphanumerical characters
    // Step 1: For inputs >= 51, produce a small number (input - 51), else 0.
    //   - _mm256_subs_epu8 = unsigned saturating subtract (never below 0).
    //   - Example: input=55 → 55-51=4; input=40 → saturates to 0.
    __m256i result = _mm256_subs_epu8(input, _mm256_set1_epi8(51));
    
    // Step 2: Mask where input < 26 (i.e., the 'A'..'Z' range).
    //   - cmpgt_epi8(26, input) produces 0xFF where 26 > input, else 0x00.
    const __m256i less = _mm256_cmpgt_epi8(_mm256_set1_epi8(26), input);

    // Step 3: For input < 26, force result index = 13.
    //   - less & 13 → byte=13 where input < 26, else 0.
    //   - OR into result so those inputs get class index 13.
    //     (All other ranges keep the earlier "input-51" or 0.)
    result = _mm256_or_si256(result, _mm256_and_si256(less, _mm256_set1_epi8(13)));

    // Step 4: Lookup table of additive ASCII offsets for each "class".
    // Indexed by `result` (0..15 possible, but only certain values used):
    //   index 0  : 'a' - 26  → lowercase start
    //   index 1..10 : '0' - 52 → digits start
    //   index 11 : '+' - 62   → plus sign
    //   index 12 : '/' - 63   → slash
    //   index 13 : 'A'        → uppercase start
    //   rest are 0 or unused.
    // Duplicated twice for both 128-bit halves (because pshufb works per lane).
    __m256i shift_LUT = _mm256_setr_epi8(
        // 0,          1         2,       3,       4,        5,        6,
        'a' - 26, '0' - 52, '0' - 52, '0' - 52, '0' - 52, '0' - 52, '0' - 52,
        //                                                             'A' at index 13
        '0' - 52, '0' - 52, '0' - 52, '0' - 52, '+' - 62, '/' - 63,     'A',      0,       0,
        'a' - 26, '0' - 52, '0' - 52, '0' - 52, '0' - 52, '0' - 52, '0' - 52,
        '0' - 52, '0' - 52, '0' - 52, '0' - 52, '+' - 62, '/' - 63,     'A',      0,       0
    );

    // Step 5: Shuffle the LUT so each byte in `result` picks its offset.
    //   - For example, if result=13 → shift='A' (65 decimal).
    //   - If result=0 → shift=('a'-26) = 71 decimal.
    result = _mm256_shuffle_epi8(shift_LUT, result);

    // Step 6: Add the shift to the original input to get the ASCII char code.
    //   - For uppercase: 'A' + input (0..25)
    //   - For lowercase: ('a'-26) + input (26..51)
    //   - For digits: ('0'-52) + input (52..61)
    //   - For '+': ('+'-62) + 62
    //   - For '/': ('/'-63) + 63
    return _mm256_add_epi8(result, input);
}


// SRP Base64 alphabet:
//   0..9   → '0'..'9'
//   10..35 → 'A'..'Z'
//   36..61 → 'a'..'z'
//   62     → '.'
//   63     → '/'

static inline __m256i lookup_pshufb_srp(__m256i input) {
    const __m256i zero = _mm256_setzero_si256();
    const __m256i hi   = _mm256_set1_epi8((char)0x80);

    // invalid if input < 0  or  input > 63
    __m256i invalid = _mm256_or_si256(
        _mm256_cmpgt_epi8(zero, input),                 // input < 0  (e.g., 0xFF sentinel)
        _mm256_cmpgt_epi8(input, _mm256_set1_epi8(63))  // input > 63
    );

    // Build class 0..4
    __m256i idx = _mm256_setzero_si256();
    idx = _mm256_sub_epi8(idx, _mm256_cmpgt_epi8(input, _mm256_set1_epi8(9)));   // >=10
    idx = _mm256_sub_epi8(idx, _mm256_cmpgt_epi8(input, _mm256_set1_epi8(35)));  // >=36
    idx = _mm256_blendv_epi8(idx, _mm256_set1_epi8(3), _mm256_cmpeq_epi8(input, _mm256_set1_epi8(62)));
    idx = _mm256_blendv_epi8(idx, _mm256_set1_epi8(4), _mm256_cmpeq_epi8(input, _mm256_set1_epi8(63)));

    // Zero-out invalid lanes via PSHUFB’s high-bit mechanism
    idx = _mm256_or_si256(idx, _mm256_and_si256(invalid, hi));

    const __m256i shift_LUT = _mm256_setr_epi8(
        '0' - 0, 'A' - 10, 'a' - 36, '.' - 62, '/' - 63, 0,0,0,0,0,0,0,0,0,0,0,
        '0' - 0, 'A' - 10, 'a' - 36, '.' - 62, '/' - 63, 0,0,0,0,0,0,0,0,0,0,0
    );

    __m256i shift = _mm256_shuffle_epi8(shift_LUT, idx);
    __m256i ascii = _mm256_add_epi8(shift, input);
    return ascii;
}


static void dump_bytes(const char *label, const uint8_t *buf, size_t len) {
    printf("%s:\n", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x ", buf[i]);
        if ((i + 1) % 16 == 0)
            printf("\n");
    }
    if (len % 16 != 0)
        printf("\n");
}


// these particular intrinsics requires immediate values, this is arguably a hack
static inline __m256i shift_right_zeros(__m256i v, int n) {
    switch (n) {
        case 0:  return v;
        case 1:  return _mm256_srli_si256(v, 1);
        case 2:  return _mm256_srli_si256(v, 2);
        case 3:  return _mm256_srli_si256(v, 3);
        case 4:  return _mm256_srli_si256(v, 4);
        case 5:  return _mm256_srli_si256(v, 5);
        case 6:  return _mm256_srli_si256(v, 6);
        case 7:  return _mm256_srli_si256(v, 7);
        case 8:  return _mm256_srli_si256(v, 8);
        case 9:  return _mm256_srli_si256(v, 9);
        case 10: return _mm256_srli_si256(v, 10);
        case 11: return _mm256_srli_si256(v, 11);
        case 12: return _mm256_srli_si256(v, 12);
        case 13: return _mm256_srli_si256(v, 13);
        case 14: return _mm256_srli_si256(v, 14);
        case 15: return _mm256_srli_si256(v, 15);
        default: return _mm256_setzero_si256(); // fallback
    }
}

static inline __m256i shift_left_zeros(__m256i v, int n) {
    switch (n) {
        case 0:  return v;
        case 1:  return _mm256_slli_si256(v, 1);
        case 2:  return _mm256_slli_si256(v, 2);
        case 3:  return _mm256_slli_si256(v, 3);
        case 4:  return _mm256_slli_si256(v, 4);
        case 5:  return _mm256_slli_si256(v, 5);
        case 6:  return _mm256_slli_si256(v, 6);
        case 7:  return _mm256_slli_si256(v, 7);
        case 8:  return _mm256_slli_si256(v, 8);
        case 9:  return _mm256_slli_si256(v, 9);
        case 10: return _mm256_slli_si256(v, 10);
        case 11: return _mm256_slli_si256(v, 11);
        case 12: return _mm256_slli_si256(v, 12);
        case 13: return _mm256_slli_si256(v, 13);
        case 14: return _mm256_slli_si256(v, 14);
        case 15: return _mm256_slli_si256(v, 15);
        case 16: return _mm256_setzero_si256(); // all bytes shifted out
        default: return _mm256_setzero_si256(); // fallback for invalid shift
    }
}

// Precomputed shuffle masks for K = 1 to 16
 const uint8_t shuffle_masks[16][16] = {
    {0x80, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14},
    {0, 0x80, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14},
    {0, 1, 0x80, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14},
    {0, 1, 2, 0x80, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14},
    {0, 1, 2, 3, 0x80, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14},
    {0, 1, 2, 3, 4, 0x80, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14},
    {0, 1, 2, 3, 4, 5, 0x80, 6, 7, 8, 9, 10, 11, 12, 13, 14},
    {0, 1, 2, 3, 4, 5, 6, 0x80, 7, 8, 9, 10, 11, 12, 13, 14},
    {0, 1, 2, 3, 4, 5, 6, 7, 0x80, 8, 9, 10, 11, 12, 13, 14},
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 0x80, 9, 10, 11, 12, 13, 14},
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0x80, 10, 11, 12, 13, 14},
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0x80, 11, 12, 13, 14},
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x80, 12, 13, 14},
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0x80, 13, 14},
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 0x80, 14},
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 0x80}};
/**

/**
 * Insert a line feed character in the 64-byte input at index K in [0,32).
 */
static inline __m256i insert_line_feed32(__m256i input, int K) {
  __m256i line_feed_vector = _mm256_set1_epi8('\n');
  __m128i identity =
      _mm_setr_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
  if (K >= 16) {
    __m128i maskhi = _mm_loadu_si128((__m128i *)shuffle_masks[K - 16]);
    __m256i mask = _mm256_set_m128i(maskhi, identity);
    __m256i lf_pos = _mm256_cmpeq_epi8(mask, _mm256_set1_epi8(0x80));
    __m256i shuffled = _mm256_shuffle_epi8(input, mask);
    __m256i result = _mm256_blendv_epi8(shuffled, line_feed_vector, lf_pos);
    return result;
  }
  // Shift input right by 1 byte
  __m256i shift = _mm256_alignr_epi8(
      input, _mm256_permute2x128_si256(input, input, 0x21), 15);
  input = _mm256_blend_epi32(input, shift, 0xF0);
  __m128i masklo = _mm_loadu_si128((__m128i *)shuffle_masks[K]);
  __m256i mask = _mm256_set_m128i(identity, masklo);
  __m256i lf_pos = _mm256_cmpeq_epi8(mask, _mm256_set1_epi8(0x80));
  __m256i shuffled = _mm256_shuffle_epi8(input, mask);
  __m256i result = _mm256_blendv_epi8(shuffled, line_feed_vector, lf_pos);
  return result;
}

typedef struct {
  __m256i vec;     // 32B with '\n' inserted in requested lanes
  uint8_t spill[2];// bytes that fell off the right; write after the 32B
  int nspill;      // 0..2
} insert_lf32_dual_result;

// Precondition: shuffle_masks[K] (K=0..15) is a 16B table where
//   - mask[K] contains 0x80 at index K (newline slot)
//   - other entries select source bytes to effect a 1-byte right shift from K..15
// extern const uint8_t shuffle_masks[16][16];

static inline insert_lf32_dual_result
insert_line_feeds32_dual(__m256i input, int k_lo, int k_hi)
{
  insert_lf32_dual_result r;
  r.nspill = 0;

  const __m128i lo128 = _mm256_castsi256_si128(input);
  const __m128i hi128 = _mm256_extracti128_si256(input, 1);

  // If we insert in the low lane, that pushes one byte into the high lane:
  // high_base = [ lo[15], hi[0], hi[1], ..., hi[14] ]
  const __m128i hi_base = (k_lo >= 0) ? _mm_alignr_epi8(hi128, lo128, 15) : hi128;

  // Spills (bytes that fall off the right end after the insertions)
  if (k_lo >= 0) {
    // With a low-lane insertion, the overall last byte that disappears is original input[31].
    r.spill[r.nspill++] = (uint8_t)_mm_extract_epi8(hi128, 15);
  }
  if (k_hi >= 0) {
    // After building hi_base, a high-lane insertion drops hi_base[15]:
    //   = input[30] if low lane also inserted, else = input[31].
    r.spill[r.nspill++] = (uint8_t)_mm_extract_epi8(hi_base, 15);
  }

  // Build per-lane shuffle masks (0x80 marks the '\n' position)
  const __m128i identity = _mm_setr_epi8(
      0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15);
  const __m128i mask_lo = (k_lo >= 0)
      ? _mm_loadu_si128((const __m128i*)shuffle_masks[k_lo])
      : identity;
  const __m128i mask_hi = (k_hi >= 0)
      ? _mm_loadu_si128((const __m128i*)shuffle_masks[k_hi])
      : identity;

  const __m256i src   = _mm256_set_m128i(hi_base, lo128);
  const __m256i mask  = _mm256_set_m128i(mask_hi, mask_lo);
  const __m256i is_lf = _mm256_cmpeq_epi8(mask, _mm256_set1_epi8((char)0x80));
  const __m256i shuf  = _mm256_shuffle_epi8(src, mask);
  const __m256i lfvec = _mm256_set1_epi8('\n');

  r.vec = _mm256_blendv_epi8(shuf, lfvec, is_lf);
  return r;
}



// Attempt to cut down on dependency chains and modulo operations
// -----------------------Custom ctx->lengths mode: 78---------------------------

//  ***** Benchmarking EVP_EncodeUpdate *****:
// Benchmark ran 50000 iterations (40000 used after warmup)
// Total elapsed (wall):     1.763151 s
// CPU cycles (avg):         163572
// Instructions (avg):       775245
// Instructions per cycle:   4.7395
// Throughput:              8.31 GB/s


//  ***** Benchmarking EVP_EncodeUpdate_openssl *****:
// Benchmark ran 50000 iterations (40000 used after warmup)
// Total elapsed (wall):     6.735597 s
// CPU cycles (avg):         711197
// Instructions (avg):       3958882
// Instructions per cycle:   5.5665
// Throughput:              2.17 GB/s


// // ---- branchless "add 32 mod stride" (valid when stride > 32) ----
// // returns (s + 32) % stride without % or /, with at most one wrap
// static inline int add32_wrap_gt32(int s, int stride) {
//     // t = s + 32 - stride
//     int t = s + 32 - stride;
//     // if t < 0 -> no wrap -> return s+32
//     // if t >= 0 -> did wrap -> return t
//     int mask = t >> 31;             // 0xFFFFFFFF if t<0, else 0
//     return (t & ~mask) | ((s + 32) & mask);
//     // same as: return (t < 0) ? (s + 32) : t;
// }

// // ---- emit one block, stride > 32 => at most one LF per 32B block ----
// static inline size_t emit_block_gt32_nomod(
//     __m256i v, uint8_t* dst, int stride, int until_nl /* = stride - s, in [1..stride] */)
// {
//     if (until_nl > 32) {               // no newline inside
//         _mm256_storeu_si256((__m256i*)dst, v);
//         return 32;
//     }
//     if (until_nl == 32) {              // boundary newline (after 32 bytes)
//         _mm256_storeu_si256((__m256i*)dst, v);
//         dst[32] = '\n';
//         return 33;
//     }
//     // in-block newline at K = 1..31
//     uint8_t last = (uint8_t)_mm256_extract_epi8(v, 31); // keep displaced last byte
//     __m256i with_lf = insert_line_feed32(v, until_nl);  // your AVX2 primitive
//     _mm256_storeu_si256((__m256i*)dst, with_lf);
//     dst[32] = last;
//     return 33;
// }

// // ---- process 4 blocks without pointer dependency & without modulo ----
// static inline size_t ins_nl_gt32_4_nochain_nomod(
//     __m256i v0, __m256i v1, __m256i v2, __m256i v3,
//     uint8_t* out, int stride, int* steps_mod_lap)
// {
//     // contract: stride > 32 (this path guarantees ≤1 LF per 32B block)
//     // assert(stride > 32);

//     // per-block starting states (no %; at most one wrap each)
//     const int s0 = *steps_mod_lap;
//     const int s1 = add32_wrap_gt32(s0, stride);
//     const int s2 = add32_wrap_gt32(s1, stride);
//     const int s3 = add32_wrap_gt32(s2, stride);
//     const int s4 = add32_wrap_gt32(s3, stride); // final state after 4 blocks

//     // until next LF for each block (in [1..stride]); no special-case needed
//     const int k0 = stride - s0;
//     const int k1 = stride - s1;
//     const int k2 = stride - s2;
//     const int k3 = stride - s3;

//     // predict bytes per block: 32 + (k <= 32 ? 1 : 0)
//     const size_t w0 = 32 + (k0 <= 32);
//     const size_t w1 = 32 + (k1 <= 32);
//     const size_t w2 = 32 + (k2 <= 32);
//     const size_t w3 = 32 + (k3 <= 32);

//     // independent destinations (no out += ... chain)
//     const size_t off0 = 0;
//     const size_t off1 = off0 + w0;
//     const size_t off2 = off1 + w1;
//     const size_t off3 = off2 + w2;
//     const size_t total = off3 + w3;

//     // emit
//     (void)emit_block_gt32_nomod(v0, out + off0, stride, k0);
//     (void)emit_block_gt32_nomod(v1, out + off1, stride, k1);
//     (void)emit_block_gt32_nomod(v2, out + off2, stride, k2);
//     (void)emit_block_gt32_nomod(v3, out + off3, stride, k3);

//     *steps_mod_lap = s4;  // already wrapped without %
//     return total;
// }

// An older attempt to break dependency chains
// Slower by about 1 Gb/s than the next version without modulo
// // assumes you have: static inline __m256i insert_line_feed32(__m256i v, int K);

// static inline size_t emit_one_block_planned(
//     __m256i v, uint8_t* dst, int stride, int until_nl /* 1..∞ */)
// {
//     // no LF inside this 32B block
//     if (until_nl > 32) {
//         _mm256_storeu_si256((__m256i*)dst, v);
//         return 32;
//     }

//     // boundary LF (exactly after 32 bytes)
//     if (until_nl == 32) {
//         _mm256_storeu_si256((__m256i*)dst, v);
//         dst[32] = '\n';
//         return 33;
//     }

//     // first LF inside at K1 ∈ [1..31]
//     uint8_t last = (uint8_t)_mm256_extract_epi8(v, 31);
//     __m256i with1 = insert_line_feed32(v, until_nl);
//     _mm256_storeu_si256((__m256i*)dst, with1);
//     size_t written = 32;
//     dst[written++] = last; // keep displaced last byte

//     // possible second LF inside at K2 = K1 + stride
//     const int K2 = until_nl + stride;
//     if (K2 <= 32) {
//         const size_t pos2 = (size_t)K2 + 1; // +1 because stream already shifted by first insert
//         const size_t tail = written - pos2;
//         memmove(dst + pos2 + 1, dst + pos2, tail);
//         dst[pos2] = '\n';
//         ++written;
//     }
//     return written; // 33 or 34
// }

// // Process 4 blocks WITHOUT an out-pointer dependency chain.
// // Returns total bytes written and updates *steps_mod_lap to state after 4 blocks.
// static inline size_t ins_nl_gt32_4_nochain(
//     __m256i v0, __m256i v1, __m256i v2, __m256i v3,
//     uint8_t* out, int stride, int* steps_mod_lap)
// {
//     // Preconditions (Option A policy)
//     // assert(stride > 0);

//     // Precompute per-block starting state (independent of how many LFs we insert)
//     const int s0 = *steps_mod_lap;
//     const int s1 = (s0 + 32) % stride;
//     const int s2 = (s1 + 32) % stride;
//     const int s3 = (s2 + 32) % stride;

//     // until next LF for each block (1..stride)
//     int k0 = stride - s0; if (k0 == 0) k0 = stride;
//     int k1 = stride - s1; if (k1 == 0) k1 = stride;
//     int k2 = stride - s2; if (k2 == 0) k2 = stride;
//     int k3 = stride - s3; if (k3 == 0) k3 = stride;

//     // Predict bytes written per block:
//     // base 32 + 1 if k<=32 (includes boundary) + 1 if k+stride<=32 (2nd LF)
//     size_t w0 = 32 + (k0 <= 32) + (k0 + stride <= 32);
//     size_t w1 = 32 + (k1 <= 32) + (k1 + stride <= 32);
//     size_t w2 = 32 + (k2 <= 32) + (k2 + stride <= 32);
//     size_t w3 = 32 + (k3 <= 32) + (k3 + stride <= 32);

//     // Prefix-sum offsets (destinations are now independent)
//     size_t off0 = 0;
//     size_t off1 = off0 + w0;
//     size_t off2 = off1 + w1;
//     size_t off3 = off2 + w2;
//     size_t total = off3 + w3;

//     // Emit with independent destinations
//     (void)emit_one_block_planned(v0, out + off0, stride, k0);
//     (void)emit_one_block_planned(v1, out + off1, stride, k1);
//     (void)emit_one_block_planned(v2, out + off2, stride, k2);
//     (void)emit_one_block_planned(v3, out + off3, stride, k3);

//     // Final lap-state after 4 blocks
//     *steps_mod_lap = (s3 + 32) % stride; // equivalently (s0 + 128) % stride
//     return total;
// }

// Takes a single 256-bit vector as input (32 bytes)
// Writes to `out`, updates steps_mod_lap, and returns bytes written (32 or 33).
// static inline size_t ins_nl_gt32(
//     __m256i v, uint8_t* out, int stride, int* steps_mod_lap)
// {
//     // Option A contract: stride must be > 0
//     // assert(stride > 0 && "stride must be > 0");
//     // printf("insert_block_with_lf32_wrapper: stride=%d steps_mod_lap=%d\n",
//     //        stride, *steps_mod_lap);
    
//     // bytes until the next newline (relative to start of this 32-byte block)
//     int until_nl = stride - *steps_mod_lap;

//     // Case A: no newline inside this block
//     if (until_nl > 32) {
//         _mm256_storeu_si256((__m256i*)out, v);
//         *steps_mod_lap = (*steps_mod_lap + 32) % stride;  // canonical update
//         return 32;
//     }

//     // Case B: newline exactly at the end (boundary; not inside the 32 bytes)
//     if (until_nl == 32) {
//         _mm256_storeu_si256((__m256i*)out, v);
//         out[32] = '\n';
//         *steps_mod_lap = 0;
//         return 33;
//     }

//     // Case C: exactly one newline falls inside the block at index [0..31]
//     // Keep the displaced last byte so total written remains 33.
//     uint8_t last = (uint8_t)_mm256_extract_epi8(v, 31);
//     __m256i with_lf = insert_line_feed32(v, until_nl); // K in [0..31]
//     _mm256_storeu_si256((__m256i*)out, with_lf);
//     out[32] = last;

//     // After inserting at 'until_nl', remaining bytes consumed in this block are (32 - until_nl)
//     *steps_mod_lap = 32 - until_nl;
//     return 33;
// }


#include <immintrin.h>
#include <stdint.h>

// --- helpers ---------------------------------------------------------------

// Extract the last byte (index 31) from a 256-bit vector
static inline uint8_t extract_last_byte(__m256i v) {
    __m128i hi = _mm256_extracti128_si256(v, 1);
    return (uint8_t)_mm_extract_epi8(hi, 15);
}

// Prepend 1 byte in front of a 32B vector, dropping the original last byte.
// Result: [carry, v[0], v[1], ..., v[30]].
static inline __m256i prepend_byte32(__m256i v, uint8_t carry) {
    // Shift right by 1 across the full 32B (with cross-lane carry)
    __m256i swapped = _mm256_permute2x128_si256(v, v, 0x21);
    __m256i shifted = _mm256_alignr_epi8(v, swapped, 15);   // [v[31], v[0], ..., v[30]]

    // Overwrite byte 0 with 'carry'
    __m128i lo = _mm256_castsi256_si128(shifted);
    lo = _mm_insert_epi8(lo, carry, 0);
    shifted = _mm256_inserti128_si256(shifted, lo, 0);
    return shifted;
}

// Your existing routine that inserts '\n' at byte offset k (0..32) inside a 32B block,
// shifting bytes [k..31) right by 1 and dropping the last (pre-insertion) byte.
// Must return exactly 32 bytes.
extern __m256i insert_line_feed32(__m256i v, int k);

// --- main: process 4 vectors with carry chaining ---------------------------
//
// Guarantees:
//   - Emits exactly four 32-byte stores for vec0..vec3.
//   - Emits at most two tiny tail bytes *after* vec3 (a '\n' and/or one data carry).
// Notes:
//   - With typical Base64 line lengths (64 or 76), the “fallback” branch never runs,
//     so there are NO tiny stores until after vec3.
//
static inline size_t ins_nl_gt32_4_carry(
    __m256i v0, __m256i v1, __m256i v2, __m256i v3,
    uint8_t* out, int stride, int* steps_mod_lap)
{
    __m256i v[4] = { v0, v1, v2, v3 };
    size_t w = 0;

    // carry of a single data byte between vectors
    uint8_t carry = 0;
    int have_carry = 0;

    for (int i = 0; i < 4; ++i) {
        __m256i x = v[i];

        // How many data bytes until the next newline should appear?
        int until = stride - *steps_mod_lap;     // can be 0..(>32)

        // If a newline is due *before any data* and we also have a pending data carry,
        // correctness demands emitting the newline first.
        if (have_carry && until == 0) {
            // Rare corner (only if the previous 32B block ended exactly at a boundary).
            out[w++] = '\n';
            *steps_mod_lap = 0;
            until = stride; // recompute logical position after the newline
        }

        // If we have a pending data carry but the upcoming newline would fall
        // *inside* the next 32 bytes, we’d need 33B this vector.
        // Fallback: flush the one-byte carry now, then continue normally.
        // With stride >= 64 this never triggers.
        if (have_carry && until <= 31) {
            out[w++] = carry;
            (*steps_mod_lap)++;   // emitted one data byte
            have_carry = 0;
            until = stride - *steps_mod_lap;
        }

        // Prepend carry (if any) so we can still store 32B exactly.
        uint8_t next_carry = 0;
        if (have_carry) {
            x = prepend_byte32(x, carry);        // [carry, v[i][0..30]]
            next_carry = extract_last_byte(v[i]); // stash original v[i][31]
        }

        // Recheck distance to newline after any updates
        until = stride - *steps_mod_lap;

        if (until > 32) {
            // A) No newline in this 32B
            _mm256_storeu_si256((__m256i*)(out + w), x);
            w += 32;
            *steps_mod_lap += 32;
            // carry persists only if we had one (it advances to v[i][31])
            if (have_carry) carry = next_carry;
        }
        else if (until == 32) {
            // B) Newline logically at the end: defer writing '\n' (keep SIMD-only here).
            _mm256_storeu_si256((__m256i*)(out + w), x);
            w += 32;
            *steps_mod_lap += 32;  // now equals 'stride' → will force until==0 next time
            if (have_carry) carry = next_carry;
        }
        else { // 1..31
            // C) One newline inside this 32B
            // IMPORTANT: This path only happens when have_carry==0 (see fallback above),
            // so the dropped byte is v[i][31], which becomes the new data carry.
            __m256i with_lf = insert_line_feed32(x, until);
            _mm256_storeu_si256((__m256i*)(out + w), with_lf);
            w += 32;

            *steps_mod_lap = 31 - until;   // bytes written after the newline
            have_carry = 1;
            carry = extract_last_byte(x);  // original last byte (v[i][31])
        }

        // If we got here with no newline inserted and no prior carry,
        // ensure have_carry stays coherent.
        if ((until > 32 || until == 32) && !have_carry) {
            // no carry is active
        } else {
            // have_carry already set appropriately above
        }
    }

    // After vec3: flush any pending newline *first* (if exactly at boundary),
    // then flush one pending data carry (if any).
    if (*steps_mod_lap == stride) {
        out[w++] = '\n';
        *steps_mod_lap = 0;
    }
    if (have_carry) {
        out[w++] = carry;
        (*steps_mod_lap)++;  // we emitted one more data byte
        if (*steps_mod_lap >= stride) {
            // extremely rare: if that byte itself completes a line, immediately emit NL
            out[w++] = '\n';
            *steps_mod_lap = 0;
        }
    }

    return w;
}



// GOOOOD!******************************* */
static inline size_t ins_nl_gt32(
    __m256i v, uint8_t* out, int stride, int* steps_mod_lap)
{
    const int until_nl = stride - *steps_mod_lap;

    // A) No newline in this block
    if (until_nl > 32) {
        _mm256_storeu_si256((__m256i*)out, v);
        *steps_mod_lap += 32;              // no wrap possible by the if-condition
        return 32;
    }

    // I can probably get rid of this by being more careful at the end. 
    // But deleting it outright doesn't seem to make a difference in performance.
    // B) Newline exactly at end
    if (until_nl == 32) {
        _mm256_storeu_si256((__m256i*)out, v);
        out[32] = '\n';
        *steps_mod_lap = 0;
        return 33;
    }

    // C) One newline inside [0..31]
    const uint8_t last = (uint8_t)_mm256_extract_epi8(v, 31);
    const __m256i with_lf = insert_line_feed32(v, until_nl);
    _mm256_storeu_si256((__m256i*)out, with_lf);
    out[32] = last;

    *steps_mod_lap = 32 - until_nl;        // in [1..31]
    return 33;
}

// ********************************************

// static inline void store33_simd(uint8_t* out, __m256i v, uint8_t tail_byte) {
//     _mm256_storeu_si256((__m256i*)out, v);
//     __m128i tail = _mm_cvtsi32_si128((int)tail_byte); // byte in lane 0, zeros elsewhere
//     _mm_storeu_si128((__m128i*)(out + 32), tail);     // safe overlapped tail
// }

// static inline uint8_t last_byte(__m256i v) {
//     __m128i hi = _mm256_extracti128_si256(v, 1);      // upper 16B
//     return (uint8_t)_mm_extract_epi8(hi, 15);         // last byte
// }

// static inline size_t ins_nl_gt32_simd(
//     __m256i v, uint8_t* out, int stride, int* steps_mod_lap)
// {
//     const int until_nl = stride - *steps_mod_lap;

//     // A) No newline in this block
//     if (until_nl > 32) {
//         _mm256_storeu_si256((__m256i*)out, v);
//         *steps_mod_lap += 32;                 // no wrap
//         return 32;
//     }

//     // B) Newline exactly at end
//     if (until_nl == 32) {
//         store33_simd(out, v, (uint8_t)'\n');
//         *steps_mod_lap = 0;
//         return 33;
//     }

//     // C) One newline inside [0..31]
//     const uint8_t tail = last_byte(v);        // the byte that overflows after insertion
//     const __m256i with_lf = insert_line_feed32(v, until_nl);
//     store33_simd(out, with_lf, tail);
//     *steps_mod_lap = 32 - until_nl;           // in [1..31]
//     return 33;
// }

// // 4-at-a-time wrapper (drop-in for your call site)
// static inline size_t ins_nl_gt32_4(
//     __m256i v0, __m256i v1, __m256i v2, __m256i v3,
//     uint8_t* out, int stride, int* steps_mod_lap)
// {
//     size_t w = 0;
//     w += ins_nl_gt32_simd(v0, out + w, stride, steps_mod_lap);
//     w += ins_nl_gt32_simd(v1, out + w, stride, steps_mod_lap);
//     w += ins_nl_gt32_simd(v2, out + w, stride, steps_mod_lap);
//     w += ins_nl_gt32_simd(v3, out + w, stride, steps_mod_lap);
//     return w;
// }

static inline size_t insert_nl_gt16(
    const __m256i v0,
    uint8_t* output,
    int steps_per_lap, // I use the analogy of a racing track where the length of a "lap" is the number of bytes between newlines
    int *steps_mod_lap // these are the numbers of steps that have been done so far in the current lap, this is used to determine where to insert the newline
) {
    int b_lane =  16; // bytes per lane
    uint8_t* out = output;

    int steps_until_nl = steps_per_lap - *steps_mod_lap; 

    _mm256_storeu_si256((__m256i*)(output),  v0);  

    if (steps_until_nl > 32) { 
        *steps_mod_lap += 32 ; 
        return 32; 
    } 

    __m256i all_ff_mask = _mm256_set1_epi8((char)0xFF);
    __m256i mask_first_lane  = _mm256_setr_epi8(
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0
    );

    __m256i mask_second_lane = _mm256_setr_epi8(
        0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF
    );

    __m256i blended_0L = v0;
    // we first check how much surplus bytes due to inserting "\n" in both lanes
    int surplus_0 =  steps_until_nl < 16 ? 1 : 0;
    
    if (surplus_0 == 1) {
        __m256i shifted_0_L = shift_left_zeros(shift_right_zeros(v0,steps_until_nl), steps_until_nl + surplus_0);   
        __m256i mask_shifted_0_L = shift_left_zeros(all_ff_mask, steps_until_nl + surplus_0);

        __m256i mask = _mm256_or_si256(mask_shifted_0_L, mask_second_lane);

        __m256i shifted_1_L = shift_left_zeros(v0, 1);

        __m256i shifted = _mm256_blendv_epi8(shifted_0_L, shifted_1_L, mask);
        blended_0L = _mm256_blendv_epi8(v0, shifted, mask);

        _mm256_storeu_si256((__m256i*)(output), blended_0L);
        steps_until_nl += steps_per_lap; 
    }  

    int surplus_1 = (16 <= steps_until_nl && steps_until_nl < 32) ? 1 : 0;
    int last_of_1L = _mm256_extract_epi8(v0, 31); 

    if (surplus_1 == 1){
        uint16_t sec_last_of_1L = _mm256_extract_epi8(v0, 30);

        int steps_until_nl_1 = steps_until_nl - 16; // we have already written 16 bytes from input

        __m256i shifted_1_L = shift_left_zeros(shift_right_zeros(v0,steps_until_nl_1), steps_until_nl_1 + surplus_0 + surplus_1);   
        __m256i mask_shifted_1_L = shift_left_zeros(all_ff_mask, steps_until_nl_1 + surplus_0 + surplus_1);
        __m256i mask = _mm256_and_si256(mask_second_lane, mask_shifted_1_L);
        __m256i blended_1L = _mm256_blendv_epi8(blended_0L, shifted_1_L, mask);

        _mm256_storeu_si256((__m256i*)(output), blended_1L);
        
        output[steps_until_nl + surplus_0] = '\n';
        output[31 + surplus_0] = sec_last_of_1L; 
        output[31 + surplus_0 + surplus_1] = last_of_1L; 

    }

    if (surplus_0 == 1) {
        output[steps_until_nl - steps_per_lap] = '\n';
        output[16] = _mm256_extract_epi8(v0, 15);
        output[31 + surplus_0 + surplus_1] = last_of_1L; 
    }

    *steps_mod_lap =  steps_until_nl >32 ? 32 - (steps_until_nl - steps_per_lap): 32 - steps_until_nl;

    int nl_at_end = 0;
    if (*steps_mod_lap == steps_per_lap || *steps_mod_lap == 0 )  {
        *steps_mod_lap = 0; 
        output[32 + surplus_0 + surplus_1] = '\n';
        nl_at_end = 1;
    }

    out += 32 + surplus_0 + surplus_1 + nl_at_end; 
    size_t written = (size_t)(out - output);

    return written;
}



static inline size_t insert_nl_2nd_vec_stride_12(
    const __m256i v0,
    uint8_t* output ,
    int dummy_stride,
    int *steps_mod_lap
) {
    // mask for inserting newlines every 4 bytes and shuffling
  __m256i shuffling_mask = _mm256_setr_epi8(
      0, 1, 2, 3, 0xFF, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 0xFF, // 14, 15
      0xFF, 0xFF, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0xFF, 12 //, 13 , 14, 15
  );

  // Prepare mask and shuffle
    __m256i shuffled = _mm256_shuffle_epi8(v0, shuffling_mask);

    _mm256_storeu_si256((__m256i*)(output + 0),  shuffled);

    int16_t rem_1_L_ext = _mm256_extract_epi16(v0, 7);
    int8_t rem_2_L_ext_P1 = _mm256_extract_epi8(v0, 29);
    int16_t rem_2_L_ext_P2 = _mm256_extract_epi16(v0, 15);

    uint8_t* out = output;
    out[4] = '\n';
    memcpy(out + 15, &rem_1_L_ext, sizeof(rem_1_L_ext));
    out[16 + 1] = '\n';
    memcpy(out + 15 + 17, &rem_2_L_ext_P1, sizeof(rem_2_L_ext_P1));
    out[16 + 14] = '\n';
    memcpy(out + 15 + 17 +1, &rem_2_L_ext_P2, sizeof(rem_2_L_ext_P2));

    out += 32 + 3;
    *steps_mod_lap = 4;

    size_t written = (out - output);  // At the end of function
    return written;
}

// Accepts 4 AVX2 vectors and inserts '\n' every stride characters
// output buffer must be at least 128 + (128 / stride) bytes
size_t insert_newlines_4avx2(__m256i v0, __m256i v1, __m256i v2, __m256i v3,
                             uint8_t *output, int stride, int *written_so_far) 
{
    uint8_t input[128];
    size_t out_idx = 0;
    int counter = *written_so_far;

    // Store the 4 vectors into a flat 128-byte array
    _mm256_storeu_si256((__m256i *)(input +  0), v0);
    _mm256_storeu_si256((__m256i *)(input + 32), v1);
    _mm256_storeu_si256((__m256i *)(input + 64), v2);
    _mm256_storeu_si256((__m256i *)(input + 96), v3);

    // Scalar loop that copies input to output, inserting newlines
    for (int i = 0; i < 128; i++) {
        output[out_idx++] = input[i];
        counter++;

        if (counter == stride) {
            output[out_idx++] = '\n';
            counter = 0;
        }
    }

    *written_so_far = counter;  // Save updated counter state for next call

    return out_idx;
}

static inline __m256i insert_newlines_by_mask(__m256i data, __m256i mask) {
    __m256i newline = _mm256_set1_epi8('\n');

    return _mm256_or_si256(
        _mm256_and_si256(mask, newline),
        _mm256_andnot_si256(mask, data)
    );
}


static inline __m256i make_newline_every_5th_byte_mask() {
    uint8_t mask_bytes[32];
    for (int i = 0; i < 32; ++i) {
        mask_bytes[i] = (i % 5 == 4) ? 0xFF : 0x00;
    }
    return _mm256_loadu_si256((__m256i*)mask_bytes);
}


static inline size_t insert_nl_str4(
    const __m256i v0,
    uint8_t* output
) {
    // mask for inserting newlines every 4 bytes and shuffling
  __m256i shuffling_mask = _mm256_setr_epi8(
      0, 1, 2, 3, 0xFF, 4, 5, 6, 7, 0xFF,
      8, 9, 10, 11,0xFF, 12, 
      // 13, 14, 15,0xFF  <-- Excess bytes that are memcopied later on
      0xFF,0xFF,0xFF, 0xFF, 0, 1, 2, 3, 0xFF, 4, 5, 6, 7, 0xFF,
      8, 9  
      // 10, 11, 0xFF, 12, 13, 14, 15 <-- Excess bytes that are memcopied later on
  );

  // Prepare mask and shuffle
    __m256i shuffled_4_bytes = _mm256_shuffle_epi8(v0, shuffling_mask);
    __m256i v0_w_nl = insert_newlines_by_mask(shuffled_4_bytes, make_newline_every_5th_byte_mask());

    _mm256_storeu_si256((__m256i*)(output + 0),  v0_w_nl);


    // Handle cross-lane remainder logic
    #define B_LANE  16 // bytes per lane
    #define N_RET_1_L  3 // excess bytes that has been "shifted out" of lane 0 after we insert newlines
    #define N_RET_2_L  (N_RET_1_L + 4) // excess bytes that has been "shifted out" of lane 1 after we insert newlines

    // bytes that were shifted out of lane 0
    __m256i rem_1_L = _mm256_srli_si256(v0, B_LANE - N_RET_1_L);

    // bytes that were shifted out of lane 1, we need to split them into two parts because there is one new line between them
    __m256i rem_2_L_P1 = _mm256_srli_si256(
        _mm256_slli_si256( 
            _mm256_srli_si256(v0, B_LANE - N_RET_2_L), 
            B_LANE - N_RET_1_L
        ),
        B_LANE - 2
    );

    // we isolate the bytes that were shifted out of lane 1 ... but only those after the newline in lane 1
    __m256i rem_2_L_P2 = _mm256_slli_si256( // 
        _mm256_srli_si256(v0, B_LANE - N_RET_2_L + N_RET_1_L), 
        N_RET_1_L);

    __m256i rem_2_L = _mm256_or_si256(rem_2_L_P1, rem_2_L_P2);

    int32_t rem_1_L_ext = _mm256_extract_epi32(rem_1_L, 0);
    int64_t rem_2_L_ext = _mm256_extract_epi64(rem_2_L, 2);

    uint8_t* out = output + 16;
    memcpy(out, &rem_1_L_ext, sizeof(rem_1_L_ext));
    out += 3;
    *out++ = '\n';

    out = output + 32;
    memcpy(out, &rem_2_L_ext, sizeof(rem_2_L_ext));
    out += 2;
    *out++ = '\n';
    out += 4;
    *out++ = '\n';

    size_t written = (out - output);  // At the end of function
    return written;
}


static inline size_t insert_nl_str8(
    const __m256i v0,
    uint8_t* output         // at least 160 bytes to be safe
) {
  __m256i shuffling_mask = _mm256_setr_epi8(
      0, 1, 2, 3, 4, 5, 6, 7, 0xFF,
      8, 9, 10, 11, 12, 13, 14, // 15,
      0xFF, 0xFF, 0, 1, 2, 3, 4, 5, 6,
      7, 0xFF,8, 9 , 10, 11,  12 
      //,13 ,14, 15 , 0xFF <-- Excess bytes that are memcopied later on
  );

  // Prepare mask and shuffle
    __m256i shuffled_4_bytes = _mm256_shuffle_epi8(v0, shuffling_mask);

    _mm256_storeu_si256((__m256i*)(output),  shuffled_4_bytes);

    int8_t rem_1_L = _mm256_extract_epi8(v0, 15);
    int8_t rem_2_L_P1 = _mm256_extract_epi8(v0, 29);
    int16_t rem_2_L_P2 = _mm256_extract_epi16(v0, 15);

    uint8_t* out = output;
    memcpy(out + 16, &rem_1_L, sizeof(rem_1_L));
    memcpy(out + 32, &rem_2_L_P1, sizeof(rem_2_L_P1));
    memcpy(out + 32+1, &rem_2_L_P2, sizeof(rem_2_L_P2));

    output[8] = '\n';
    output[17] = '\n';
    output[26] = '\n';
    output[35] = '\n';
    
    out += 32 + 4;

    size_t written = (out - output);  // At the end of function
    return written;
}

    int encode_base64_avx2(EVP_ENCODE_CTX *ctx,char *dst, const char *src, size_t srclen, int *final_steps_mod_lap) {
        const uint8_t *input = (const uint8_t *)src;
        uint8_t *out = (uint8_t *)dst;
        size_t i = 0;
        int stride = ctx->length / 3 * 4; 
        int steps_mod_lap = 0;  
        const int use_srp = ctx && (ctx->flags & EVP_ENCODE_CTX_USE_SRP_ALPHABET);

        // Define shuffle mask for AVX2
        const __m256i shuf = _mm256_set_epi8(
            10, 11, 9, 10, 7, 8, 6, 7, 4, 5, 3, 4, 1, 2, 0, 1,
            10, 11, 9, 10, 7, 8, 6, 7, 4, 5, 3, 4, 1, 2, 0, 1);

        int base = 0;

        // Process 96 bytes at a time
        for (; i + 100 <= srclen; i += 96) {
            // We shave off 4 bytes from the beginning and the end
            const __m128i lo0 = _mm_loadu_si128((const __m128i *)(input + i + 4 * 3 * 0));
            const __m128i hi0 = _mm_loadu_si128((const __m128i *)(input + i + 4 * 3 * 1));
            const __m128i lo1 = _mm_loadu_si128((const __m128i *)(input + i + 4 * 3 * 2));
            const __m128i hi1 = _mm_loadu_si128((const __m128i *)(input + i + 4 * 3 * 3));
            const __m128i lo2 = _mm_loadu_si128((const __m128i *)(input + i + 4 * 3 * 4));
            const __m128i hi2 = _mm_loadu_si128((const __m128i *)(input + i + 4 * 3 * 5));
            const __m128i lo3 = _mm_loadu_si128((const __m128i *)(input + i + 4 * 3 * 6));
            const __m128i hi3 = _mm_loadu_si128((const __m128i *)(input + i + 4 * 3 * 7));

            // ******************* EXPANDING 6 bits to more bits***************************
            // Fig . 1 in the paper
            __m256i in0 = _mm256_shuffle_epi8(_mm256_set_m128i(hi0, lo0), shuf);
            __m256i in1 = _mm256_shuffle_epi8(_mm256_set_m128i(hi1, lo1), shuf);
            __m256i in2 = _mm256_shuffle_epi8(_mm256_set_m128i(hi2, lo2), shuf);
            __m256i in3 = _mm256_shuffle_epi8(_mm256_set_m128i(hi3, lo3), shuf);

            const __m256i t0_0 = _mm256_and_si256(in0, _mm256_set1_epi32(0x0fc0fc00));
            const __m256i t0_1 = _mm256_and_si256(in1, _mm256_set1_epi32(0x0fc0fc00));
            const __m256i t0_2 = _mm256_and_si256(in2, _mm256_set1_epi32(0x0fc0fc00));
            const __m256i t0_3 = _mm256_and_si256(in3, _mm256_set1_epi32(0x0fc0fc00));

            const __m256i t1_0 = _mm256_mulhi_epu16(t0_0, _mm256_set1_epi32(0x04000040));
            const __m256i t1_1 = _mm256_mulhi_epu16(t0_1, _mm256_set1_epi32(0x04000040));
            const __m256i t1_2 = _mm256_mulhi_epu16(t0_2, _mm256_set1_epi32(0x04000040));
            const __m256i t1_3 = _mm256_mulhi_epu16(t0_3, _mm256_set1_epi32(0x04000040));

            const __m256i t2_0 = _mm256_and_si256(in0, _mm256_set1_epi32(0x003f03f0));
            const __m256i t2_1 = _mm256_and_si256(in1, _mm256_set1_epi32(0x003f03f0));
            const __m256i t2_2 = _mm256_and_si256(in2, _mm256_set1_epi32(0x003f03f0));
            const __m256i t2_3 = _mm256_and_si256(in3, _mm256_set1_epi32(0x003f03f0));

            const __m256i t3_0 = _mm256_mullo_epi16(t2_0, _mm256_set1_epi32(0x01000010));
            const __m256i t3_1 = _mm256_mullo_epi16(t2_1, _mm256_set1_epi32(0x01000010));
            const __m256i t3_2 = _mm256_mullo_epi16(t2_2, _mm256_set1_epi32(0x01000010));
            const __m256i t3_3 = _mm256_mullo_epi16(t2_3, _mm256_set1_epi32(0x01000010));

            const __m256i input0 = _mm256_or_si256(t1_0, t3_0);
            const __m256i input1 = _mm256_or_si256(t1_1, t3_1);
            const __m256i input2 = _mm256_or_si256(t1_2, t3_2);
            const __m256i input3 = _mm256_or_si256(t1_3, t3_3);

            // ******************* END EXPANDING 6 bits to more bits***************************
            __m256i vec0;
            __m256i vec1;
            __m256i vec2;
            __m256i vec3;

            if (use_srp){
                vec0 = lookup_pshufb_srp(input0);
                vec1 = lookup_pshufb_srp(input1);
                vec2 = lookup_pshufb_srp(input2);
                vec3 = lookup_pshufb_srp(input3);
                
            } else 
            {
                vec0 = lookup_pshufb_std(input0);
                vec1 = lookup_pshufb_std(input1);
                vec2 = lookup_pshufb_std(input2);
                vec3 = lookup_pshufb_std(input3);
            }

            if (stride == 0) {
                _mm256_storeu_si256((__m256i *)out, vec0);
                out += 32;
                _mm256_storeu_si256((__m256i *)out, vec1);
                out += 32;
                _mm256_storeu_si256((__m256i *)out, vec2);
                out += 32;
                _mm256_storeu_si256((__m256i *)out, vec3);
                out += 32;
            }  else if (stride == 64) {
                _mm256_storeu_si256((__m256i *)out, vec0);
                out += 32;
                _mm256_storeu_si256((__m256i *)out, vec1);
                out += 32;
                *(out++) = '\n';

                _mm256_storeu_si256((__m256i *)out, vec2);
                out += 32;

                _mm256_storeu_si256((__m256i *)out, vec3);
                out += 32;

                *(out++) = '\n';
            }
            else if (stride == 4) {

                int out_idx = 0;
                out_idx += insert_nl_str4(vec0, out + out_idx);
                out_idx += insert_nl_str4(vec1, out + out_idx);
                out_idx += insert_nl_str4(vec2, out + out_idx);
                out_idx += insert_nl_str4(vec3, out + out_idx);

                out += out_idx; 
            }
            else if (stride == 8) {          

                out += insert_nl_str8(
                    vec0, out );
                out += insert_nl_str8(
                    vec1, out );
                out += insert_nl_str8(
                    vec2, out );
                out += insert_nl_str8(
                    vec3, out );

            }
            else if (stride == 12) {          
                typedef size_t (*InsertFn)(__m256i vec, uint8_t* out, int stride, int* steps_mod_lap);

                // int base = (i /96) % 3;
                //  base = (i /96) % 3;

                // attempt #1
                // Benchmark ran 50000 iterations (40000 used after warmup)
                // Total elapsed (wall):     7.510144 s
                // CPU cycles (avg):         759968
                // Instructions (avg):       2792014
                // Instructions per cycle:   3.6739
                // Throughput:              3.72 GB/s

                //  ***** Benchmarking EVP_EncodeUpdate_openssl *****:
                //     Benchmark ran 50000 iterations (40000 used after warmup)
                //     Total elapsed (wall):     16.884286 s
                //     CPU cycles (avg):         1800592
                //     Instructions (avg):       10105065
                //     Instructions per cycle:   5.6121
                //     Throughput:              1.66 GB/s

                // static const uint8_t seq[3][4] = {
                //     {0,1,2,0},
                //     {1,2,0,1},
                //     {2,0,1,2}
                // };

                // InsertFn fns[3] = {
                //     insert_nl_gt16,
                //     insert_nl_2nd_vec_stride_12,
                //     insert_nl_gt16
                // };

                // out += fns[ seq[base][0] ](vec0, out, stride, &steps_mod_lap);
                // out += fns[ seq[base][1] ](vec1, out, stride, &steps_mod_lap);
                // out += fns[ seq[base][2] ](vec2, out, stride, &steps_mod_lap);
                // out += fns[ seq[base][3] ](vec3, out, stride, &steps_mod_lap);

                // base = (base == 2) ? 0 : base + 1;  // 0→1→2→0…



                // attempt #2
                // performance was similar to previous one with this approach:
                // InsertFn insert_fns[3] = {
                //     insert_nl_gt16,
                //     insert_nl_2nd_vec_stride_12,
                //     insert_nl_gt16,
                //     insert_nl_gt16
                // };

                // out += insert_fns[(base + 0) % 3](vec0, out, stride, &steps_mod_lap);
                // out += insert_fns[(base + 1) % 3](vec1, out, stride, &steps_mod_lap);
                // out += insert_fns[(base + 2) % 3](vec2, out, stride, &steps_mod_lap);
                // out += insert_fns[(base + 3) % 3](vec3, out, stride, &steps_mod_lap);
            
                // attempt #3

                // ***** Benchmarking EVP_EncodeUpdate *****:
                // Benchmark ran 50000 iterations (40000 used after warmup)
                // Total elapsed (wall):     5.628161 s
                // CPU cycles (avg):         606264
                // Instructions (avg):       2420874
                // Instructions per cycle:   3.9931
                // Throughput:              4.97 GB/s

                // base must be 0,1,2 (e.g., carried across iterations: if (++base==3) base=0)
                switch (base) {
                case 0:
                    
                    // int steps_mod_lap_1 = 0;
                    // int steps_mod_lap_2 = 0;
                    // int steps_mod_lap_3 = 0;
                    // int steps_mod_lap_4 = 0;

                    out += insert_nl_gt16(vec0, out, stride, &steps_mod_lap);
                    out += insert_nl_2nd_vec_stride_12(vec1, out, stride, &steps_mod_lap);
                    out += insert_nl_gt16(vec2, out, stride, &steps_mod_lap);
                    out += insert_nl_gt16(vec3, out, stride, &steps_mod_lap);
                    break;
                case 1:
                    out += insert_nl_2nd_vec_stride_12(vec0, out, stride, &steps_mod_lap);
                    out += insert_nl_gt16(vec1, out, stride, &steps_mod_lap);
                    out += insert_nl_gt16(vec2, out, stride, &steps_mod_lap);
                    out += insert_nl_2nd_vec_stride_12(vec3, out, stride, &steps_mod_lap);
                    break;
                default: /* base == 2 */
                    out += insert_nl_gt16(vec0, out, stride, &steps_mod_lap);
                    out += insert_nl_gt16(vec1, out, stride, &steps_mod_lap);
                    out += insert_nl_2nd_vec_stride_12(vec2, out, stride, &steps_mod_lap);
                    out += insert_nl_gt16(vec3, out, stride, &steps_mod_lap);
                    break;
                }

                // advance phase cheaply (avoid % 3)
                if (++base == 3) base = 0;

                // switch (base) {
                // case 0:
                    
                //     // int steps_mod_lap_1 = 0;
                //     // int steps_mod_lap_2 = 0;
                //     // int steps_mod_lap_3 = 0;
                //     // int steps_mod_lap_4 = 0;

                //     insert_nl_gt16(vec0, out, stride, &steps_mod_lap);
                //     out += 32 + 1;
                //     insert_nl_2nd_vec_stride_12(vec1, out, stride, &steps_mod_lap);
                //     out += 32 + 5;
                //     insert_nl_gt16(vec2, out, stride, &steps_mod_lap);
                //     out += 32 + 1;
                //     insert_nl_gt16(vec3, out, stride, &steps_mod_lap);
                //     out += 32 + 1;
                //     break;
                // case 1:
                //     out += insert_nl_2nd_vec_stride_12(vec0, out, stride, &steps_mod_lap);
                //     out += insert_nl_gt16(vec1, out, stride, &steps_mod_lap);
                //     out += insert_nl_gt16(vec2, out, stride, &steps_mod_lap);
                //     out += insert_nl_2nd_vec_stride_12(vec3, out, stride, &steps_mod_lap);
                //     break;
                // default: /* base == 2 */
                //     out += insert_nl_gt16(vec0, out, stride, &steps_mod_lap);
                //     out += insert_nl_gt16(vec1, out, stride, &steps_mod_lap);
                //     out += insert_nl_2nd_vec_stride_12(vec2, out, stride, &steps_mod_lap);
                //     out += insert_nl_gt16(vec3, out, stride, &steps_mod_lap);
                //     break;
                // }

                // // advance phase cheaply (avoid % 3)
                // if (++base == 3) base = 0;

                
            }
            else if ( 32 <= stride   ){
                out += ins_nl_gt32(
                    vec0, out, stride, &steps_mod_lap);
                out += ins_nl_gt32(
                    vec1, out, stride, &steps_mod_lap);
                out += ins_nl_gt32(
                    vec2, out, stride, &steps_mod_lap);
                out += ins_nl_gt32(
                    vec3, out, stride, &steps_mod_lap);

                // out += ins_nl_gt32_4_carry(vec0, vec1, vec2, vec3, out, stride, &steps_mod_lap);


                // out += ins_nl_gt32_4(vec0, vec1, vec2, vec3, out, stride, &steps_mod_lap);

                // size_t produced = ins_nl_gt32_4_nochain_nomod(vec0, vec1, vec2, vec3, out, stride, &steps_mod_lap);
                // out += produced;  // single increment at the end

            }
            else if ( 16 <= stride   ){
                out += insert_nl_gt16(
                    vec0, out, stride, &steps_mod_lap);
                out += insert_nl_gt16(
                    vec1, out, stride, &steps_mod_lap);
                out += insert_nl_gt16(
                    vec2, out, stride, &steps_mod_lap);
                out += insert_nl_gt16(
                    vec3, out, stride, &steps_mod_lap);
            }
            else {
                printf("Unsupported stride: %d\n", stride);

                // int out_idx = 0;
                // int newlines_inserted = 0;
                // out_idx = insert_newlines_4avx2(vec0, 
                //                     vec1, 
                //                     vec2, 
                //                     vec3, out, stride, &newlines_inserted);

                // out += out_idx; 

            }

        }

        if (stride == 0) {
            // Process remaining 24-byte chunks
            for (; i + 28 <= srclen; i += 24) {
                // lo = [xxxx|DDDC|CCBB|BAAA]
                // hi = [xxxx|HHHG|GGFF|FEEE]
                const __m128i lo = _mm_loadu_si128((const __m128i *)(input + i));
                const __m128i hi = _mm_loadu_si128((const __m128i *)(input + i + 4 * 3));
                
                // bytes from groups A, B and C are needed in separate 32-bit lanes
                // in = [0HHH|0GGG|0FFF|0EEE[0DDD|0CCC|0BBB|0AAA]
                __m256i in = _mm256_shuffle_epi8(_mm256_set_m128i(hi, lo), shuf);
                
                // See comments in C++ SSE code and/or paper
                const __m256i t0 = _mm256_and_si256(in, _mm256_set1_epi32(0x0fc0fc00));
                const __m256i t1 = _mm256_mulhi_epu16(t0, _mm256_set1_epi32(0x04000040));
                const __m256i t2 = _mm256_and_si256(in, _mm256_set1_epi32(0x003f03f0));
                const __m256i t3 = _mm256_mullo_epi16(t2, _mm256_set1_epi32(0x01000010));
                const __m256i indices = _mm256_or_si256(t1, t3);

                _mm256_storeu_si256(
                    (__m256i *)out,
                    (use_srp ? lookup_pshufb_srp : lookup_pshufb_std)(indices)
                );
                out += 32;
            }
        }
        *final_steps_mod_lap = steps_mod_lap;

        // Return number of bytes written
        return (size_t)(out - (uint8_t *)dst) +
                + evp_encode_scalar_nl_int(ctx, out, src + i, srclen - i, final_steps_mod_lap);
    }

#endif

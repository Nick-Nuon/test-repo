// #if defined(__x86_64__) && defined(__AVX2__)

#include <immintrin.h>
#include <openssl/evp.h>
#include <stddef.h>
#include <stdint.h>
#include "enc_b64_scalar.h"

static __m256i lookup_pshufb_improved_std(__m256i input) {
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


int encode_base64_avx2(EVP_ENCODE_CTX *ctx,char *dst, const char *src, size_t srclen) {
    const uint8_t *input = (const uint8_t *)src;
    uint8_t *out = (uint8_t *)dst;
    size_t i = 0;

    // Define shuffle mask for AVX2
    const __m256i shuf = _mm256_set_epi8(
        10, 11, 9, 10, 7, 8, 6, 7, 4, 5, 3, 4, 1, 2, 0, 1,
        10, 11, 9, 10, 7, 8, 6, 7, 4, 5, 3, 4, 1, 2, 0, 1);

    // Process 96 bytes at a time
    for (; i + 100 <= srclen; i += 96) {
        const __m128i lo0 = _mm_loadu_si128((const __m128i *)(input + i + 4 * 3 * 0));
        const __m128i hi0 = _mm_loadu_si128((const __m128i *)(input + i + 4 * 3 * 1));
        const __m128i lo1 = _mm_loadu_si128((const __m128i *)(input + i + 4 * 3 * 2));
        const __m128i hi1 = _mm_loadu_si128((const __m128i *)(input + i + 4 * 3 * 3));
        const __m128i lo2 = _mm_loadu_si128((const __m128i *)(input + i + 4 * 3 * 4));
        const __m128i hi2 = _mm_loadu_si128((const __m128i *)(input + i + 4 * 3 * 5));
        const __m128i lo3 = _mm_loadu_si128((const __m128i *)(input + i + 4 * 3 * 6));
        const __m128i hi3 = _mm_loadu_si128((const __m128i *)(input + i + 4 * 3 * 7));

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

        _mm256_storeu_si256((__m256i *)out, lookup_pshufb_improved_std(input0));
        out += 32;
        _mm256_storeu_si256((__m256i *)out, lookup_pshufb_improved_std(input1));
        out += 32;
        _mm256_storeu_si256((__m256i *)out, lookup_pshufb_improved_std(input2));
        out += 32;
        _mm256_storeu_si256((__m256i *)out, lookup_pshufb_improved_std(input3));
        out += 32;
    }

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

        _mm256_storeu_si256((__m256i *)out, lookup_pshufb_improved_std(indices));
        out += 32;
    }

    // Return number of bytes written
    return i / 3 * 4 
            + evp_encode_scalar_nl_int(NULL, out, src + i, srclen - i);
}


// #endif

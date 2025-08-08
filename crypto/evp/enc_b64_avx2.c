#include <string.h>

#if (defined(__x86_64__) || defined(_M_AMD64)) && !defined(_M_ARM64EC)

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


// these particular intrinsics requires immediate values, this is arguably a hack , but 
// it works and it beats using macros.
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

size_t insert_newlines_simd_block_gt32_stride(
    const __m256i v0,
    uint8_t* output,
    int steps_per_lap, // I use the analogy of a racing track where the length of a "lap" is the number of bytes between newlines
    int *steps_mod_lap // these are the numbers of steps that have been done so far in the current lap, this is used to determine where to insert the newline
) {

    printf("--------------------------------------------------\n");
    // Handle cross-lane remainder logic
    int b_lane =  16; // bytes per lane
    uint8_t* out = output;

    int steps_until_nl = steps_per_lap - *steps_mod_lap; 

    // if (steps_until_nl < 0) {
    //     printf("steps_until_nl < 0!!!!!");
    //     printf("\033[1;31msteps_until_nl: %d\033[0m\n", steps_until_nl);
    //     return -1;
    // }

    printf("steps_until_nl: %d\n", steps_until_nl);
    printf("steps_mod_lap: %d\n", *steps_mod_lap);

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
        printf("newline in first lane!: %d\n", surplus_0);
        __m256i shifted_0_L = shift_left_zeros(shift_right_zeros(v0,steps_until_nl), steps_until_nl + surplus_0);   
        __m256i mask_shifted_0_L = shift_left_zeros(all_ff_mask, steps_until_nl + surplus_0);

        __m256i mask = _mm256_or_si256(mask_shifted_0_L, mask_second_lane);

        __m256i shifted_1_L = shift_left_zeros(v0, 1);

        // Blend the second lane of shifted_1_L into shifted_0_L using mask_1_l
        __m256i shifted = _mm256_blendv_epi8(shifted_0_L, shifted_1_L, mask);
        blended_0L = _mm256_blendv_epi8(v0, shifted, mask);

        _mm256_storeu_si256((__m256i*)(output), blended_0L);
        steps_until_nl += steps_per_lap; 
    }  

    // printf("steps_until_nl after adding steps_per_lap: %d\n", steps_until_nl);
    int surplus_1 = (16 <= steps_until_nl && steps_until_nl < 32) ? 1 : 0;


    int last_of_1L = _mm256_extract_epi8(v0, 31); 

    if (surplus_1 == 1){
        printf("Newline in second lane!: %d\n", surplus_1);

        uint16_t sec_last_of_1L = _mm256_extract_epi8(v0, 30);

        int steps_until_nl_1 = steps_until_nl - 16; // we have already written 16 bytes from input

        __m256i shifted_1_L = shift_left_zeros(shift_right_zeros(v0,steps_until_nl_1), steps_until_nl_1 + surplus_0 + surplus_1);   
        __m256i mask_shifted_1_L = shift_left_zeros(all_ff_mask, steps_until_nl_1 + surplus_0 + surplus_1);

        __m256i mask = _mm256_and_si256(mask_second_lane, mask_shifted_1_L);

        // printf("shifted_1_L:"); print_avx2_bytes(shifted_1_L);

        // printf("mask 1L:"); print_avx2_bytes(mask);

        __m256i blended_1L = _mm256_blendv_epi8(blended_0L, shifted_1_L, mask);

        // printf("blended 1L:"); print_avx2_bytes(blended_1L);

        _mm256_storeu_si256((__m256i*)(output), blended_1L);
        
        output[steps_until_nl + surplus_0] = '\n';

        output[31 + surplus_0] = sec_last_of_1L; 
        output[31 + surplus_0 + surplus_1] = last_of_1L; 

    }

    if (surplus_0 == 1) {
        printf("Inserting newline due to first lane!\n");
        output[steps_until_nl - steps_per_lap] = '\n';
        output[16] = _mm256_extract_epi8(v0, 15);
        output[31 + surplus_0 + surplus_1] = last_of_1L; 
    }

    *steps_mod_lap =  steps_until_nl >32 ? 32 - (steps_until_nl - steps_per_lap): 32 - steps_until_nl;
    // printf("\033[1;34msteps_mod_lap (after): %d\033[0m\n", *steps_mod_lap);

    int nl_at_end = 0;
    if (*steps_mod_lap == steps_per_lap || *steps_mod_lap == 0 )  {
        printf("Inserting newline at the end!\n");
        *steps_mod_lap = 0; 
        output[32 + surplus_0 + surplus_1] = '\n';
        nl_at_end = 1;
    }



    out += 32 + surplus_0 + surplus_1 + nl_at_end; 

    // Print the output buffer in hex and ASCII for debugging
    dump_bytes("hasbeen output", output, out - output);

    size_t written = (size_t)(out - output);
    printf("written: %zu\n", written);

    return written;
}



size_t insert_nl_2nd_avx2_stride_12(
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
//written_so_far is what has been written so far
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

    // dump_bytes("Input to insert_newlines_4avx2", input, 128);

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
    // dump_bytes("output to insert_newlines_4avx2", output, 128);

    return out_idx;
}

__m256i insert_newlines_by_mask(__m256i data, __m256i mask) {
    __m256i newline = _mm256_set1_epi8('\n');

    return _mm256_or_si256(
        _mm256_and_si256(mask, newline),
        _mm256_andnot_si256(mask, data)
    );
}


__m256i make_newline_every_5th_byte_mask() {
    uint8_t mask_bytes[32];
    for (int i = 0; i < 32; ++i) {
        mask_bytes[i] = (i % 5 == 4) ? 0xFF : 0x00;
    }
    return _mm256_loadu_si256((__m256i*)mask_bytes);
}


size_t insert_newlines_simd_block_from_input(
    const __m256i v0,
    uint8_t* output         // at least 160 bytes to be safe
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

    int encode_base64_avx2(EVP_ENCODE_CTX *ctx,char *dst, const char *src, size_t srclen, int ctx_length, int *final_steps_mod_lap) {
        const uint8_t *input = (const uint8_t *)src;
        uint8_t *out = (uint8_t *)dst;
        size_t i = 0;
        size_t nl_count = 0;
        int stride = ctx_length / 3 * 4; 
        int steps_mod_lap = 0;

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

            printf("*** New 4x block! ***\n");

            if (stride == 0) {
                _mm256_storeu_si256((__m256i *)out, lookup_pshufb_improved_std(input0));
                out += 32;
                _mm256_storeu_si256((__m256i *)out, lookup_pshufb_improved_std(input1));
                out += 32;
                _mm256_storeu_si256((__m256i *)out, lookup_pshufb_improved_std(input2));
                out += 32;
                _mm256_storeu_si256((__m256i *)out, lookup_pshufb_improved_std(input3));
                out += 32;
            }  else if (stride == 64) {
                _mm256_storeu_si256((__m256i *)out, lookup_pshufb_improved_std(input0));
                out += 32;
                _mm256_storeu_si256((__m256i *)out, lookup_pshufb_improved_std(input1));
                out += 32;
                *(out++) = '\n';
                nl_count++;

                _mm256_storeu_si256((__m256i *)out, lookup_pshufb_improved_std(input2));
                out += 32;

                _mm256_storeu_si256((__m256i *)out, lookup_pshufb_improved_std(input3));
                out += 32;

                *(out++) = '\n';
                nl_count++;
            }
            else if (stride == 4) {

                // Mula files
                //  ***** Benchmarking EVP_EncodeUpdate *****:
                // Benchmark ran 50000 iterations (40000 used after warmup)
                // Total elapsed (wall):     1.532642 s
                // CPU cycles (avg):         144214
                // Instructions (avg):       558339
                // Instructions per cycle:   3.8716
                // Throughput:              9.56 GB/s


                //  ***** Benchmarking EVP_EncodeUpdate_openssl *****:
                // Benchmark ran 50000 iterations (40000 used after warmup)
                // Total elapsed (wall):     14.830337 s
                // CPU cycles (avg):         1606042
                // Instructions (avg):       8301569
                // Instructions per cycle:   5.1690
                // Throughput:              0.99 GB/s

                int out_idx = 0;
                out_idx += insert_newlines_simd_block_from_input(lookup_pshufb_improved_std(input0), out + out_idx);
                out_idx += insert_newlines_simd_block_from_input(lookup_pshufb_improved_std(input1), out + out_idx);
                out_idx += insert_newlines_simd_block_from_input(lookup_pshufb_improved_std(input2), out + out_idx);
                out_idx += insert_newlines_simd_block_from_input(lookup_pshufb_improved_std(input3), out + out_idx);

                out += out_idx; 
                // nl_count += 128 / stride; // 128 bytes / 3 bytes per base64 character * 4 characters per base64 block
                nl_count += (128 + stride - 1) / stride;

            }


            else if (stride == 12) {          
                typedef size_t (*InsertFn)(__m256i vec, uint8_t* out, int stride, int* steps_mod_lap);

                InsertFn insert_fns[3] = {
                    insert_newlines_simd_block_gt32_stride,
                    insert_nl_2nd_avx2_stride_12,
                    insert_newlines_simd_block_gt32_stride,
                    insert_newlines_simd_block_gt32_stride
                };

                int base = (i /96) % 3;

                out += insert_fns[(base + 0) % 3](lookup_pshufb_improved_std(input0), out, stride, &steps_mod_lap);
                out += insert_fns[(base + 1) % 3](lookup_pshufb_improved_std(input1), out, stride, &steps_mod_lap);
                out += insert_fns[(base + 2) % 3](lookup_pshufb_improved_std(input2), out, stride, &steps_mod_lap);
                out += insert_fns[(base + 3) % 3](lookup_pshufb_improved_std(input3), out, stride, &steps_mod_lap);

                nl_count += (128 + stride - 1) / stride;

                     }
            else if ( 16 <= stride   ){
                out += insert_newlines_simd_block_gt32_stride(
                    lookup_pshufb_improved_std(input0), out, stride, &steps_mod_lap);
                out += insert_newlines_simd_block_gt32_stride(
                    lookup_pshufb_improved_std(input1), out, stride, &steps_mod_lap);
                out += insert_newlines_simd_block_gt32_stride(
                    lookup_pshufb_improved_std(input2), out, stride, &steps_mod_lap);
                out += insert_newlines_simd_block_gt32_stride(
                    lookup_pshufb_improved_std(input3), out, stride, &steps_mod_lap);
                nl_count += (128 + stride - 1) / stride;
            }
            else {
                // Mula files
                // ***** Benchmarking EVP_EncodeUpdate *****:
                // Benchmark ran 50000 iterations (40000 used after warmup)
                // Total elapsed (wall):     8.876706 s
                // CPU cycles (avg):         921862
                // Instructions (avg):       4606748
                // Instructions per cycle:   4.9972
                // Throughput:              1.65 GB/s


                // ***** Benchmarking EVP_EncodeUpdate_openssl *****:
                // Benchmark ran 50000 iterations (40000 used after warmup)
                // Total elapsed (wall):     14.980089 s
                // CPU cycles (avg):         1611686
                // Instructions (avg):       8301569
                // Instructions per cycle:   5.1509
                // Throughput:              0.98 GB/s

                int out_idx = 0;
                int newlines_inserted = 0;
                out_idx = insert_newlines_4avx2(lookup_pshufb_improved_std(input0), 
                                    lookup_pshufb_improved_std(input1), 
                                    lookup_pshufb_improved_std(input2), 
                                    lookup_pshufb_improved_std(input3), out, stride, &newlines_inserted);

                out += out_idx; 
                nl_count += 128 / stride;
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

                _mm256_storeu_si256((__m256i *)out, lookup_pshufb_improved_std(indices));
                out += 32;
            }
        }

        *final_steps_mod_lap = steps_mod_lap;

        // Return number of bytes written
        return i / 3 * 4 + nl_count + 
                + evp_encode_scalar_nl_int(ctx, out, src + i, srclen - i, final_steps_mod_lap);
    }

#endif

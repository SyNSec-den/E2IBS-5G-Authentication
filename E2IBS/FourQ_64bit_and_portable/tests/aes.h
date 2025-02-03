#include <stdint.h>
#include "params.h"
#include <wmmintrin.h>
#include <emmintrin.h>
#include <smmintrin.h>

typedef  __m128i block; //a block is 128-bit

static inline block toBlock(uint8_t*data) { return _mm_set_epi64x(((uint64_t*)data)[1], ((uint64_t*)data)[0]);}
static inline block toBlockLow(uint64_t low_u64)        { return _mm_set_epi64x(0, low_u64); }
static inline block toBlockBoth(uint64_t high_u64, uint64_t low_u64) { return _mm_set_epi64x(high_u64, low_u64); }

// Encrypts the vector of blocks {baseIdx, baseIdx + 1, ..., baseIdx + length - 1} 
// and writes the result to cyphertext.
void ecbEncCounterMode(uint64_t baseIdx, uint64_t length, block* cyphertext);
void setKey(block userKey);


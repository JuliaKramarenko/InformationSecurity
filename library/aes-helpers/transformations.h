#ifndef AES_KALYNA_LIBRARY_AES_HELPERS_TRANSFORMATIONS_H_
#define AES_KALYNA_LIBRARY_AES_HELPERS_TRANSFORMATIONS_H_

#include <cstdint>
#include <cstdio>

// multiply on x
uint8_t Xtime(uint8_t b);

uint8_t MulBytes(uint8_t a, uint8_t b);

uint32_t GetPaddingLength(uint32_t len, size_t block_bytes_len);

uint8_t *PaddingNulls(uint8_t in[], uint32_t inLen, uint32_t alignLen);

uint8_t *IncrementCtr(uint8_t in[], uint32_t len);

void MixColumns(uint8_t **state);

void MixSingleColumn(uint8_t *r);

void SubWord(uint8_t *a);

void RotWord(uint8_t *a);

void XorWords(const uint8_t *a, const uint8_t *b, uint8_t *c);

void Rcon(uint8_t *a, size_t n);

void XorBlocks(const uint8_t *a, const uint8_t *b, uint8_t *c, uint32_t len);

void SubBytes(uint8_t **state, size_t words_in_blocks);

// shift row i on n positions
void ShiftRow(uint8_t **state, size_t i, size_t n, size_t words_in_block);

void ShiftRows(uint8_t **state, size_t words_in_block);

void AddRoundKey(uint8_t **state, const uint8_t *key, size_t words_in_block);

void InvSubBytes(uint8_t **state, size_t words_in_block);

void InvMixColumns(uint8_t **state, size_t words_in_block);

void InvShiftRows(uint8_t **state, size_t words_in_block);

#endif //AES_KALYNA_LIBRARY_AES_HELPERS_TRANSFORMATIONS_H_

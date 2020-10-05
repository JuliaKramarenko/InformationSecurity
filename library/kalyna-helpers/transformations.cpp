#include <cstring>
#include <cstdlib>

#include "transformations.h"
#include "tables.h"

/*!
 * Index a byte array as cipher state matrix.
 */
#define INDEX(table, row, col) table[(row) + (col) * sizeof(uint64_t)]

void SubBytes(uint64_t *state, size_t nb) {
  uint64_t *s = state;
  for (size_t i = 0; i < nb; ++i) {
    state[i] = sboxes_enc[0][s[i] & 0x00000000000000FFULL] |
        ((uint64_t) sboxes_enc[1][(s[i] & 0x000000000000FF00ULL) >> 8u] << 8u) |
        ((uint64_t) sboxes_enc[2][(s[i] & 0x0000000000FF0000ULL) >> 16u] << 16u) |
        ((uint64_t) sboxes_enc[3][(s[i] & 0x00000000FF000000ULL) >> 24u] << 24u) |
        ((uint64_t) sboxes_enc[0][(s[i] & 0x000000FF00000000ULL) >> 32u] << 32u) |
        ((uint64_t) sboxes_enc[1][(s[i] & 0x0000FF0000000000ULL) >> 40u] << 40u) |
        ((uint64_t) sboxes_enc[2][(s[i] & 0x00FF000000000000ULL) >> 48u] << 48u) |
        ((uint64_t) sboxes_enc[3][(s[i] & 0xFF00000000000000ULL) >> 56u] << 56u);
  }
}

void InvSubBytes(uint64_t *state, size_t nb) {
  uint64_t *s = state;
  for (size_t i = 0; i < nb; ++i) {
    state[i] = sboxes_dec[0][s[i] & 0x00000000000000FFULL] |
        ((uint64_t) sboxes_dec[1][(s[i] & 0x000000000000FF00ULL) >> 8u] << 8u) |
        ((uint64_t) sboxes_dec[2][(s[i] & 0x0000000000FF0000ULL) >> 16u] << 16u) |
        ((uint64_t) sboxes_dec[3][(s[i] & 0x00000000FF000000ULL) >> 24u] << 24u) |
        ((uint64_t) sboxes_dec[0][(s[i] & 0x000000FF00000000ULL) >> 32u] << 32u) |
        ((uint64_t) sboxes_dec[1][(s[i] & 0x0000FF0000000000ULL) >> 40u] << 40u) |
        ((uint64_t) sboxes_dec[2][(s[i] & 0x00FF000000000000ULL) >> 48u] << 48u) |
        ((uint64_t) sboxes_dec[3][(s[i] & 0xFF00000000000000ULL) >> 56u] << 56u);
  }
}

void ShiftRows(uint64_t *&state, size_t nb) {
  int shift = -1;

  uint8_t *byte_state = WordsToBytes(nb, state);
  auto *nstate = (uint8_t *) malloc(nb * sizeof(uint64_t));

  for (size_t row = 0; row < sizeof(uint64_t); ++row) {
    if (row % (sizeof(uint64_t) / nb) == 0)
      shift += 1;
    for (size_t col = 0; col < nb; ++col) {
      INDEX(nstate, row, (col + shift) % nb) = INDEX(byte_state, row, col);
    }
  }

  state = BytesToWords(nb * sizeof(uint64_t), nstate);
  free(byte_state);
}

void InvShiftRows(uint64_t *&state, size_t nb) {
  int shift = -1;

  uint8_t *byte_state = WordsToBytes(nb, state);
  auto *nstate = (uint8_t *) malloc(nb * sizeof(uint64_t));

  for (size_t row = 0; row < sizeof(uint64_t); ++row) {
    if (row % (sizeof(uint64_t) / nb) == 0)
      shift += 1;
    for (size_t col = 0; col < nb; ++col) {
      INDEX(nstate, row, col) = INDEX(byte_state, row, (col + shift) % nb);
    }
  }

  state = BytesToWords(nb * sizeof(uint64_t), nstate);
  free(byte_state);
}

uint8_t MultiplyGF(uint8_t x, uint8_t y) {
  uint8_t r = 0;
  for (size_t i = 0; i < kBITS_IN_BYTE; ++i) {
    if ((y & 0x1u) == 1)
      r ^= x;
    const uint8_t high_bit = x & 0x80u;
    x <<= 1u;
    if (high_bit == 0x80)
      x ^= kREDUCTION_POLYNOMIAL;
    y >>= 1u;
  }
  return r;
}

void MatrixMultiply(uint64_t *state, size_t nb, const uint8_t matrix[8][8]) {
  uint8_t *byte_state = WordsToBytes(nb, state);

  for (int col = 0; col < nb; ++col) {
    uint64_t result = 0;
    for (int row = sizeof(uint64_t) - 1; row >= 0; --row) {
      uint8_t product = 0;
      for (int b = sizeof(uint64_t) - 1; b >= 0; --b) {
        product ^= MultiplyGF(INDEX(byte_state, b, col), matrix[row][b]);
      }
      result |= (uint64_t) product << (row * sizeof(uint64_t));
    }
    state[col] = result;
  }
}

void MixColumns(uint64_t *state, size_t nb) {
  MatrixMultiply(state, nb, mds_matrix);
}

void InvMixColumns(uint64_t *state, size_t nb) {
  MatrixMultiply(state, nb, mds_inv_matrix);
}

void EncipherRound(uint64_t *&state, size_t nb) {
  SubBytes(state, nb);
  ShiftRows(state, nb);
  MixColumns(state, nb);
}

void DecipherRound(uint64_t *&state, size_t nb) {
  InvMixColumns(state, nb);
  InvShiftRows(state, nb);
  InvSubBytes(state, nb);
}

void AddRoundKey(int round, uint64_t *state, uint64_t **round_keys, size_t nb) {
  for (size_t i = 0; i < nb; ++i) {
    state[i] = state[i] + round_keys[round][i];
  }
}

void SubRoundKey(int round, uint64_t *state, uint64_t **round_keys, size_t nb) {
  for (size_t i = 0; i < nb; ++i) {
    state[i] = state[i] - round_keys[round][i];
  }
}

void AddRoundKeyExpand(const uint64_t *value, uint64_t *state, size_t nb) {
  for (size_t i = 0; i < nb; ++i) {
    state[i] = state[i] + value[i];
  }
}

void XorRoundKey(int round, uint64_t *state, uint64_t **round_keys, size_t nb) {
  for (size_t i = 0; i < nb; ++i) {
    state[i] = state[i] ^ round_keys[round][i];
  }
}

void XorRoundKeyExpand(const uint64_t *value, uint64_t *state, size_t nb) {
  for (size_t i = 0; i < nb; ++i) {
    state[i] = state[i] ^ value[i];
  }
}

void Rotate(size_t state_size, uint64_t *state_value) {
  uint64_t temp = state_value[0];
  for (size_t i = 1; i < state_size; ++i) {
    state_value[i - 1] = state_value[i];
  }
  state_value[state_size - 1] = temp;
}

void ShiftLeft(size_t state_size, uint64_t *state_value) {
  for (size_t i = 0; i < state_size; ++i) {
    state_value[i] <<= 1u;
  }
}

void RotateLeft(size_t state_size, uint64_t *&state_value) {
  size_t rotate_bytes = 2 * state_size + 3;
  size_t bytes_num = state_size * (kBITS_IN_WORD / kBITS_IN_BYTE);

  uint8_t *bytes = WordsToBytes(state_size, state_value);
  auto *buffer = (uint8_t *) malloc(rotate_bytes);

  /* Rotate bytes in memory. */
  memcpy(buffer, bytes, rotate_bytes);
  memmove(bytes, bytes + rotate_bytes, bytes_num - rotate_bytes);
  memcpy(bytes + bytes_num - rotate_bytes, buffer, rotate_bytes);

  state_value = BytesToWords(bytes_num, bytes);

  free(buffer);
}

uint8_t *WordsToBytes(size_t length, uint64_t *words) {
  uint8_t *bytes;
  if (IsBigEndian()) {
    for (size_t i = 0; i < length; ++i) {
      words[i] = ReverseWord(words[i]);
    }
  }
  bytes = (uint8_t *) words;
  return bytes;
}

uint64_t *BytesToWords(size_t length, uint8_t *bytes) {
  auto *words = (uint64_t *) bytes;
  if (IsBigEndian()) {
    for (size_t i = 0; i < length; ++i) {
      words[i] = ReverseWord(words[i]);
    }
  }
  return words;
}

uint64_t ReverseWord(uint64_t word) {
  uint64_t reversed = 0;
  auto *src = (uint8_t *) &word;
  auto *dst = (uint8_t *) &reversed;

  for (size_t i = 0; i < sizeof(uint64_t); ++i) {
    dst[i] = src[sizeof(uint64_t) - i];
  }
  return reversed;
}

int IsBigEndian() {
  unsigned int num = 1;
  /* Check the least significant byte value to determine endianness */
  return (*((uint8_t *) &num) == 0);
}


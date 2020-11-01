#include "tables.h"
#include "transformations.h"

#include <cstring>
uint8_t *IncrementCtr(uint8_t in[], uint32_t len){
  for (int i=len-1, carry=1; i>=0 && carry; i--){
    carry = !++in[i];}
  return in;
}

uint8_t *PaddingNulls(uint8_t in[], uint32_t inLen, uint32_t alignLen) {
  auto *alignIn = new uint8_t[alignLen];
  memcpy(alignIn, in, inLen);
  memset(alignIn + inLen, 0x00, alignLen - inLen);
  return alignIn;
}

// multiply on x
uint8_t Xtime(uint8_t b) {
  return ((unsigned) b << 1u) ^ ((((unsigned) b >> 7u) & 1u) * 0x1b);
}

void MixSingleColumn(uint8_t *r) {
  // The array 'a' is simply a copy of the input array 'r'
  // The array 'b' is each element of the array 'a' multiplied by 2 in Rijndael's Galois field
  // a[n] ^ b[n] is element n multiplied by 3 in Rijndael's Galois field
  uint8_t a[4];
  uint8_t b[4];
  for (uint8_t c = 0; c < 4; c++) {
    a[c] = r[c];
    // h is 0xff if the high bit of r[c] is set, 0 otherwise
    // arithmetic right shift, thus shifting in either zeros or ones
    const auto h = (uint8_t) ((int8_t) r[c] >> 7u);
    // implicitly removes high bit because b[c] is an 8-bit char, so we xor by 0x1b and not 0x11b in the next line
    b[c] = r[c] << 1u;
    // Rijndael's Galois field
    b[c] ^= 0x1Bu & h;
  }
  // 2 * a0 + a3 + a2 + 3 * a1
  r[0] = (unsigned) b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1];
  // 2 * a1 + a0 + a3 + 3 * a2
  r[1] = (unsigned) b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2];
  // 2 * a2 + a1 + a0 + 3 * a3
  r[2] = (unsigned) b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3];
  // 2 * a3 + a2 + a1 + 3 * a0
  r[3] = (unsigned) b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0];
}

void MixColumns(uint8_t **state) {
  auto *temp = new uint8_t[4];

  for (int i = 0; i < 4; ++i) {
    for (int j = 0; j < 4; ++j) {
      temp[j] = state[j][i];
    }
    MixSingleColumn(temp);
    for (int j = 0; j < 4; ++j) {
      state[j][i] = temp[j];
    }
  }
  delete[] temp;
}

void SubWord(uint8_t *a) {
  for (size_t i = 0; i < 4; i++) {
    a[i] = sbox[a[i] / 16][a[i] % 16];
  }
}

void RotWord(uint8_t *a) {
  const uint8_t c = a[0];
  a[0] = a[1];
  a[1] = a[2];
  a[2] = a[3];
  a[3] = c;
}

void XorWords(const uint8_t *a, const uint8_t *b, uint8_t *c) {
  for (size_t i = 0; i < 4; i++) {
    c[i] = a[i] ^ b[i];
  }
}

void Rcon(uint8_t *a, size_t n) {
  uint8_t c = 1;
  for (size_t i = 0; i < n - 1; i++) {
    c = Xtime(c);
  }

  a[0] = c;
  a[1] = a[2] = a[3] = 0;
}

// multiplication a and b in galois field
uint8_t MulBytes(uint8_t a, uint8_t b) {
  uint8_t p = 0;
  uint8_t high_bit_mask = 0x80;
  // x^8 + x^4 + x^3 + x + 1
  uint8_t modulo = 0x1B;

  for (int i = 0; i < 8; i++) {
    if (b & 1u) {
      p ^= a;
    }

    const uint8_t high_bit = a & high_bit_mask;
    a <<= 1u;
    if (high_bit) {
      a ^= modulo;
    }
    b >>= 1u;
  }

  return p;
}

void XorBlocks(const uint8_t *a, const uint8_t *b, uint8_t *c, uint32_t len) {
  for (uint32_t i = 0; i < len; i++) {
    c[i] = a[i] ^ b[i];
  }
}

uint32_t GetPaddingLength(uint32_t len, size_t block_bytes_len) {
  uint32_t lengthWithPadding = (len / block_bytes_len);
  if (len % block_bytes_len) {
    lengthWithPadding++;
  }

  lengthWithPadding *= block_bytes_len;

  return lengthWithPadding;
}

void SubBytes(uint8_t **state, size_t words_in_blocks) {
  for (size_t i = 0; i < 4; i++) {
    for (size_t j = 0; j < words_in_blocks; j++) {
      const uint8_t t = state[i][j];
      state[i][j] = sbox[t / 16][t % 16];
    }
  }

}

// shift row i on n positions
void ShiftRow(uint8_t **state, size_t i, size_t n, size_t words_in_block) {
  uint8_t tmp[words_in_block];
  for (size_t j = 0; j < words_in_block; j++) {
    tmp[j] = state[i][(j + n) % words_in_block];
  }
  memcpy(state[i], tmp, words_in_block * sizeof(uint8_t));
}

void ShiftRows(uint8_t **state, size_t words_in_block) {
  ShiftRow(state, 1, 1, words_in_block);
  ShiftRow(state, 2, 2, words_in_block);
  ShiftRow(state, 3, 3, words_in_block);
}

void AddRoundKey(uint8_t **state, const uint8_t *key, size_t words_in_block) {
  for (size_t i = 0; i < 4; i++) {
    for (size_t j = 0; j < words_in_block; j++) {
      state[i][j] = state[i][j] ^ key[i + 4 * j];
    }
  }
}

void InvSubBytes(uint8_t **state, size_t words_in_block) {
  for (size_t i = 0; i < 4; i++) {
    for (size_t j = 0; j < words_in_block; j++) {
      const uint8_t t = state[i][j];
      state[i][j] = inv_sbox[t / 16][t % 16];
    }
  }
}

void InvMixColumns(uint8_t **state, size_t words_in_block) {
  uint8_t s[4], s1[4];

  for (size_t j = 0; j < words_in_block; j++) {

    for (size_t i = 0; i < 4; i++) {
      s[i] = state[i][j];
    }

    s1[0] = (unsigned) MulBytes(0x0e, s[0]) ^ MulBytes(0x0b, s[1]) ^ MulBytes(0x0d, s[2]) ^ MulBytes(0x09, s[3]);
    s1[1] = (unsigned) MulBytes(0x09, s[0]) ^ MulBytes(0x0e, s[1]) ^ MulBytes(0x0b, s[2]) ^ MulBytes(0x0d, s[3]);
    s1[2] = (unsigned) MulBytes(0x0d, s[0]) ^ MulBytes(0x09, s[1]) ^ MulBytes(0x0e, s[2]) ^ MulBytes(0x0b, s[3]);
    s1[3] = (unsigned) MulBytes(0x0b, s[0]) ^ MulBytes(0x0d, s[1]) ^ MulBytes(0x09, s[2]) ^ MulBytes(0x0e, s[3]);

    for (size_t i = 0; i < 4; i++) {
      state[i][j] = s1[i];
    }
  }
}

void InvShiftRows(uint8_t **state, size_t words_in_block) {
  ShiftRow(state, 1, words_in_block - 1, words_in_block);
  ShiftRow(state, 2, words_in_block - 2, words_in_block);
  ShiftRow(state, 3, words_in_block - 3, words_in_block);
}

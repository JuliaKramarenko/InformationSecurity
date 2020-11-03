#include <stdexcept>

#include "kupyna.h"
#include "tables.h"
#include "stdlib.h"
#include "string.h"
#include "stdio.h"
#include "../kupyna-helpers/tables.h"

Kupyna::Kupyna(size_t b_num)
{
  switch (b_num) {
    case 256: {
      Init(rounds_num_512, b_num_512, state_byte_size_512, b_num);
      break;
    }
    case 512: {
      Init(rounds_num_1024, b_num_1024, state_byte_size_1024, b_num);
      break;
    }
    default: {
      throw std::invalid_argument("Incorrect number of bits");
    }
  }
}

void Kupyna::Hash(uint8_t * msg, size_t msg_bit_len, uint8_t * hash_code)
{
  memset(state, 0, bytes_num);
  state[0][0] = bytes_num;

  PadBlock(msg, msg_bit_len);
  Digest(msg);
  OutputTransformation(hash_code);
}

void Kupyna::Init(const size_t in_rounds, const size_t in_columns, const size_t in_bytes_num, const size_t in_hash_b_num)
{
  rounds = in_rounds;
  columns_count = in_columns;
  bytes_num = in_bytes_num;
  hash_b_num = in_hash_b_num;

  memset(state, 0, bytes_num);
  state[0][0] = bytes_num;
}

void Kupyna::SubBytes(uint8_t state[b_num_1024][rows_count], int columns)
{
  int i, j;
  uint8_t temp[b_num_1024];
  for (i = 0; i < rows_count; ++i) {
    for (j = 0; j < columns; ++j) {
      state[j][i] = sboxes_k[i % 4][state[j][i]];
    }
  }
}

void Kupyna::ShiftBytes(uint8_t state[b_num_1024][rows_count], int columns)
{
  int i, j;
  uint8_t temp[b_num_1024];
  int shift = -1;
  for (i = 0; i < rows_count; ++i) {
    if ((i == rows_count - 1) && (columns == b_num_1024)) {
      shift = 11;
    }
    else {
      ++shift;
    }
    for (j = 0; j < columns; ++j) {
      temp[(j + shift) % columns] = state[j][i];
    }
    for (j = 0; j < columns; ++j) {
      state[j][i] = temp[j];
    }
  }
}

void Kupyna::MixColumns(uint8_t state[b_num_1024][rows_count], int columns)
{
  int i, row, col, b;
  uint8_t product;
  uint8_t result[rows_count];
  for (col = 0; col < columns; ++col) {
    memset(result, rows_count, 0);
    for (row = rows_count - 1; row >= 0; --row) {
      product = 0;
      for (b = rows_count - 1; b >= 0; --b) {
        product ^= GFMult(state[col][b], mds_matrix_k[row][b]);
      }
      result[row] = product;
    }
    for (i = 0; i < rows_count; ++i) {
      state[col][i] = result[i];
    }
  }
}

void Kupyna::AddRoundConstantP(uint8_t state[b_num_1024][rows_count], int columns, int round)
{
  int i;
  for (i = 0; i < columns; ++i)
  {
    state[i][0] ^= (i * 0x10) ^ round;
  }
}

void Kupyna::AddRoundConstantQ(uint8_t state[b_num_1024][rows_count], int columns, int round)
{
  int j;
  uint64_t* s = (uint64_t*)state;
  for (j = 0; j < columns; ++j)
  {
    s[j] = s[j] + (0x00F0F0F0F0F0F0F3ULL ^ ((((columns - j - 1) * 0x10ULL) ^ round) << (7 * 8)));
  }
}

void Kupyna::P(uint8_t state[b_num_1024][rows_count])
{
  int i;
  for (i = 0; i < rounds; ++i) {
    AddRoundConstantP(state, columns_count, i);
    SubBytes(state, columns_count);
    ShiftBytes(state, columns_count);
    MixColumns(state, columns_count);
  }
}

void Kupyna::Q(uint8_t state[b_num_1024][rows_count])
{
  int i;
  for (i = 0; i < rounds; ++i) {
    AddRoundConstantQ(state, columns_count, i);
    SubBytes(state, columns_count);
    ShiftBytes(state, columns_count);
    MixColumns(state, columns_count);
  }
}

std::uint8_t Kupyna::GFMult(uint8_t x, uint8_t y)
{
  int i;
  uint8_t r = 0;
  uint8_t hbit = 0;
  for (i = 0; i < b_byte_size; ++i) {
    if ((y & 0x1) == 1)
      r ^= x;
    hbit = x & 0x80;
    x <<= 1;
    if (hbit == 0x80)
      x ^= reduction_polinomial;
    y >>= 1;
  }
  return r;
}

int Kupyna::PadBlock(uint8_t* msg_block, size_t size)
{
  int i;
  int mask;
  int pad_bit;
  int extra_bits;
  int zero_nbytes;
  size_t msg_nbytes = size / b_byte_size;
  size_t nblocks = msg_nbytes / bytes_num;
  pad_bytes_num = msg_nbytes - (nblocks * bytes_num);
  data_bytes_num = msg_nbytes - pad_bytes_num;
  uint8_t* pad_start = msg_block + data_bytes_num;
  extra_bits = size % b_byte_size;
  if (extra_bits) {
    pad_bytes_num += 1;
  }
  memcpy(padding, pad_start, pad_bytes_num);
  extra_bits = size % b_byte_size;
  if (extra_bits) {
    mask = ~(0xFF >> (extra_bits));
    pad_bit = 1 << (7 - extra_bits);
    padding[pad_bytes_num - 1] = (padding[pad_bytes_num - 1] & mask) | pad_bit;
  }
  else {
    padding[pad_bytes_num] = 0x80;
    pad_bytes_num += 1;
  }
  zero_nbytes = ((-size - 97) % (bytes_num * b_byte_size)) / b_byte_size;
  memset(padding + pad_bytes_num, 0, zero_nbytes);
  pad_bytes_num += zero_nbytes;
  for (i = 0; i < (96 / 8); ++i, ++pad_bytes_num) {
    if (i < sizeof(size_t)) {
      padding[pad_bytes_num] = (size >> (i * 8)) & 0xFF;
    }
    else {
      padding[pad_bytes_num] = 0;
    }
  }
  return 0;
}

void Kupyna::Digest(uint8_t* msg_block)
{
  int b, i, j;
  uint8_t temp1[b_num_1024][rows_count];
  uint8_t temp2[b_num_1024][rows_count];
  for (b = 0; b < data_bytes_num; b += bytes_num) {
    for (i = 0; i < rows_count; ++i) {
      for (j = 0; j < columns_count; ++j) {
        temp1[j][i] = state[j][i] ^ msg_block[b + j * rows_count + i];
        temp2[j][i] = msg_block[b + j * rows_count + i];
      }
    }
    P(temp1);
    Q(temp2);
    for (i = 0; i < rows_count; ++i) {
      for (j = 0; j < columns_count; ++j) {
        state[j][i] ^= temp1[j][i] ^ temp2[j][i];
      }
    }
  }

  for (b = 0; b < pad_bytes_num; b += bytes_num) {
    for (i = 0; i < rows_count; ++i) {
      for (j = 0; j < columns_count; ++j) {
        temp1[j][i] = state[j][i] ^ padding[b + j * rows_count + i];
        temp2[j][i] = padding[b + j * rows_count + i];
      }
    }
    P(temp1);
    Q(temp2);
    for (i = 0; i < rows_count; ++i) {
      for (j = 0; j < columns_count; ++j) {
        state[j][i] ^= temp1[j][i] ^ temp2[j][i];
      }
    }
  }
}

void Kupyna::Trunc(uint8_t* hash_code)
{
  int i;
  size_t hash_nbytes = hash_b_num / b_byte_size;
  memcpy(hash_code, (uint8_t*)state + bytes_num - hash_nbytes, hash_nbytes);
}

void Kupyna::OutputTransformation(uint8_t* hash_code)
{
  int i, j;
  uint8_t temp[b_num_1024][rows_count];
  memcpy(temp, state, rows_count * b_num_1024);
  P(temp);
  for (i = 0; i < rows_count; ++i) {
    for (j = 0; j < columns_count; ++j) {
      state[j][i] ^= temp[j][i];
    }
  }
  Trunc(hash_code);
}

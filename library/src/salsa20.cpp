#include <stdexcept>

#include "salsa20.h"

Salsa20::Salsa20(int keyLen)
{
  switch (keyLen) {
    case 128: {
      sizeKey = 128;
      break;
    }
    case 256: {
      sizeKey = 256;
      break;
    }
    default: {
      throw std::invalid_argument("Incorrect key length");
    }
  }
}

bool Salsa20::Encrypt(uint8_t* key, uint8_t nonce[8], uint32_t si, uint8_t* buf, uint32_t buflen)
{
  uint8_t keystream[64] = { 0 };
  uint8_t n[16] = { 0 };
  uint32_t i;

  if (key == nullptr || nonce == nullptr || buf == nullptr)
    return false;

  for (i = 0; i < 8; ++i)
    n[i] = nonce[i];

  if (si % 64 != 0) {
    RevLittleEndian(n + 8, si / 64);
    sizeKey == 128? Expand16(key, n, keystream) : Expand32(key, n, keystream);
  }

  for (i = 0; i < buflen; ++i) {
    if ((si + i) % 64 == 0) {
      RevLittleEndian(n + 8, ((si + i) / 64));
    }

    buf[i] ^= keystream[(si + i) % 64];
  }

  return true;
}

bool Salsa20::Decrypt(uint8_t* key, uint8_t nonce[8], uint32_t si, uint8_t* buf, uint32_t buflen)
{
  return Encrypt(key, nonce, si, buf, buflen);
}
uint32_t Salsa20::RotL(uint32_t value, int shift)
{
  return (value << shift) | (value >> (32 - shift));
}

void Salsa20::QuarterRound(uint32_t* y0, uint32_t* y1, uint32_t* y2, uint32_t* y3)
{
  *y1 = *y1 ^ RotL(*y0 + *y3, 7);
  *y2 = *y2 ^ RotL(*y1 + *y0, 9);
  *y3 = *y3 ^ RotL(*y2 + *y1, 13);
  *y0 = *y0 ^ RotL(*y3 + *y2, 18);
}

void Salsa20::RowRound(uint32_t y[16])
{
  QuarterRound(&y[0], &y[1], &y[2], &y[3]);
  QuarterRound(&y[5], &y[6], &y[7], &y[4]);
  QuarterRound(&y[10], &y[11], &y[8], &y[9]);
  QuarterRound(&y[15], &y[12], &y[13], &y[14]);
}

void Salsa20::ColumnRound(uint32_t x[16])
{
  QuarterRound(&x[0], &x[4], &x[8], &x[12]);
  QuarterRound(&x[5], &x[9], &x[13], &x[1]);
  QuarterRound(&x[10], &x[14], &x[2], &x[6]);
  QuarterRound(&x[15], &x[3], &x[7], &x[11]);
}

void Salsa20::DoubleRound(uint32_t x[16])
{
  ColumnRound(x);
  RowRound(x);
}

// Creates a little-endian word from 4 bytes pointed to by b
uint32_t Salsa20::LittleEndian(uint8_t* b)
{
  return b[0] + ((uint_fast16_t)b[1] << 8) + ((uint_fast32_t)b[2] << 16) + ((uint_fast32_t)b[3] << 24);
}

// Moves the little-endian word into the 4 bytes pointed to by b
void Salsa20::RevLittleEndian(uint8_t* b, uint32_t w)
{
  b[0] = w;
  b[1] = w >> 8;
  b[2] = w >> 16;
  b[3] = w >> 24;
}

void Salsa20::Hash(uint8_t seq[64])
{
  int i;
  uint32_t x[16];
  uint32_t z[16];

  for (i = 0; i < 16; ++i)
    x[i] = z[i] = LittleEndian(seq + (4 * i));

  for (i = 0; i < 10; ++i)
    DoubleRound(z);

  for (i = 0; i < 16; ++i) {
    z[i] += x[i];
    RevLittleEndian(seq + (4 * i), z[i]);
  }
}
void Salsa20::Expand16(uint8_t* k,uint8_t n[16],uint8_t keystream[64])
{
  int i, j;
  uint8_t t[4][4] = {
      { 'e', 'x', 'p', 'a' },
      { 'n', 'd', ' ', '1' },
      { '6', '-', 'b', 'y' },
      { 't', 'e', ' ', 'k' }
  };
  for (i = 0; i < 64; i += 20)
    for (j = 0; j < 4; ++j)
      keystream[i + j] = t[i / 20][j];

  for (i = 0; i < 16; ++i) {
    keystream[4 + i] = k[i];
    keystream[44 + i] = k[i];
    keystream[24 + i] = n[i];
  }

  Hash(keystream);
}
void Salsa20::Expand32(uint8_t* k, uint8_t n[16], uint8_t keystream[64])
{
  int i, j;
  uint8_t o[4][4] = {
      { 'e', 'x', 'p', 'a' },
      { 'n', 'd', ' ', '3' },
      { '2', '-', 'b', 'y' },
      { 't', 'e', ' ', 'k' }
  };
  for (i = 0; i < 64; i += 20)
    for (j = 0; j < 4; ++j)
      keystream[i + j] = o[i / 20][j];
  for (i = 0; i < 16; ++i) {
    keystream[4 + i] = k[i];
    keystream[44 + i] = k[i + 16];
    keystream[24 + i] = n[i];
  }

  Hash(keystream);
}

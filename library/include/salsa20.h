#ifndef AES_KALYNA_SALSA20_H
#define AES_KALYNA_SALSA20_H
#include <cstdint>
#include <cstdio>
#include <stddef.h>

/**
 * Return codes for s20_crypt
 */

class Salsa20 {
 public:
  explicit Salsa20(int keylen = 256);

  bool Encrypt(uint8_t* key, uint8_t nonce[8], uint32_t si, uint8_t* buf, uint32_t buflen);
  bool Decrypt(uint8_t* key, uint8_t nonce[8], uint32_t si, uint8_t* buf, uint32_t buflen);

 private:
  uint32_t RotL(uint32_t value, int shift);
  void QuarterRound(uint32_t* y0, uint32_t* y1, uint32_t* y2, uint32_t* y3);
  void RowRound(uint32_t y[16]);
  void ColumnRound(uint32_t x[16]);
  void DoubleRound(uint32_t x[16]);
  uint32_t LittleEndian(uint8_t* b);
  void RevLittleEndian(uint8_t* b, uint32_t w);
  void Hash(uint8_t seq[64]);
  void Expand16(uint8_t* k, uint8_t n[16], uint8_t keystream[64]);
  void Expand32(uint8_t* k, uint8_t n[16], uint8_t keystream[64]);

  uint8_t* key;
  size_t sizeKey;
  uint8_t nonce[8];
  uint32_t si;
  uint8_t* buf;
  uint32_t buflen;

};

#endif //AES_KALYNA_SALSA20_H

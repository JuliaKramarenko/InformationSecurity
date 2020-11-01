#ifndef AES_KALYNA_LIBRARY_INCLUDE_AES_H_
#define AES_KALYNA_LIBRARY_INCLUDE_AES_H_

#include <cstdint>
#include <cstdio>

class AES {
 public:
  explicit AES(int keyLen = 256);

  uint8_t *EncryptECB(uint8_t in[], uint32_t inLen, uint8_t key[], uint32_t &outLen);

  uint8_t *DecryptECB(uint8_t in[], uint32_t inLen, uint8_t key[]);

  uint8_t *EncryptCBC(uint8_t in[], uint32_t inLen, uint8_t key[], uint8_t *iv, uint32_t &outLen);

  uint8_t *DecryptCBC(uint8_t in[], uint32_t inLen, uint8_t key[], uint8_t *iv);

  uint8_t *EncryptCFB(uint8_t in[], uint32_t s, uint32_t inLen, uint8_t key[], uint8_t *iv, uint32_t &outLen);

  uint8_t *DecryptCFB(uint8_t in[], uint32_t s, uint32_t inLen, uint8_t key[], uint8_t *iv);

  uint8_t *EncryptOFB(uint8_t in[], uint32_t inLen, uint8_t key[], uint8_t *iv, uint32_t &outLen);

  uint8_t *DecryptOFB(uint8_t in[], uint32_t inLen, uint8_t key[], uint8_t *iv);

  uint8_t *EncryptCTR(uint8_t in[], uint32_t inLen, uint8_t key[], uint32_t &outLen);

  uint8_t *DecryptCTR(uint8_t in[], uint32_t inLen, uint8_t key[]);

 private:
  void KeyExpansion(const uint8_t key[], uint8_t w[]) const;

  void EncryptBlock(const uint8_t in[], uint8_t out[], const uint8_t key[]) const;

  void DecryptBlock(const uint8_t in[], uint8_t out[], const uint8_t key[]) const;

 private:
  const size_t Nb = 4;
  const size_t blockBytesLen = 4 * Nb * sizeof(uint8_t);

  size_t Nk, Nr;
};

#endif //AES_KALYNA_LIBRARY_INCLUDE_AES_H_

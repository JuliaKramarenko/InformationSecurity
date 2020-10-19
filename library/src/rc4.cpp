#include <stdexcept>

#include "rc4.h"

void RC4::SetKey(uint8_t k[], uint32_t keyLen) {
  if (1 <= keyLen && keyLen <= 256) {
    sizeKey = keyLen;

    prgaIndexI = 0;
    prgaIndexJ = 0;
    for (int i = 0; i < 256; i++) {
      sbox[i] = i;
    }

    KSA(k);
  } else
    throw std::invalid_argument("Incorrect key length");
}

void RC4::Encrypt(uint8_t plaintext[], uint8_t ciphertext[], uint32_t Len) {
  PRGA(plaintext, ciphertext, Len);
}

void RC4::KSA(uint8_t *key) {
  uint32_t j = 0;
  for (uint32_t i = 0; i < 256; i++) {
    j = (j + sbox[i] + key[i % sizeKey]) % 256;
    Swap(sbox, i, j);
  }
}

void RC4::Swap(uint8_t data[], uint32_t i, uint32_t j) {
  uint8_t temp = data[i];
  data[i] = data[j];
  data[j] = temp;
}

void RC4::PRGA(uint8_t plaintext[], uint8_t cipher[], uint32_t Len) {
  for (uint32_t k = 0; k < Len; k++) {
    prgaIndexI = (prgaIndexI + 1) % 256;
    prgaIndexJ = (prgaIndexJ + sbox[prgaIndexI]) % 256;
    Swap(sbox, prgaIndexI, prgaIndexJ);
    cipher[k] = sbox[(sbox[prgaIndexI] + sbox[prgaIndexJ]) % 256] ^ plaintext[k];
  }
} 
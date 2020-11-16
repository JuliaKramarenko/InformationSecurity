#include <cstring>
#include <stdexcept>

#include <iostream>

#include "aes.h"
#include "transformations.h"

AES::AES(int keyLen) {
  switch (keyLen) {
    case 128: {
      Nk = 4;
      Nr = 10;
      break;
    }
    case 192: {
      Nk = 6;
      Nr = 12;
      break;
    }
    case 256: {
      Nk = 8;
      Nr = 14;
      break;
    }
    default: {
      throw std::invalid_argument("Incorrect key length");
    }
  }
}

uint8_t *AES::EncryptECB(uint8_t in[], uint32_t inLen, uint8_t key[], uint32_t &outLen) {
  outLen = GetPaddingLength(inLen, blockBytesLen);
  uint8_t *alignIn = PaddingNulls(in, inLen, outLen);
  auto *out = new uint8_t[outLen];
  auto *roundKeys = new uint8_t[4 * Nb * (Nr + 1)];
  KeyExpansion(key, roundKeys);
  for (uint32_t i = 0; i < outLen; i += blockBytesLen) {
    EncryptBlock(alignIn + i, out + i, roundKeys);
  }

  delete[] alignIn;
  delete[] roundKeys;

  return out;
}

uint8_t *AES::DecryptECB(uint8_t in[], uint32_t inLen, uint8_t key[]) {
  auto *out = new uint8_t[inLen];
  auto *roundKeys = new uint8_t[4 * Nb * (Nr + 1)];
  KeyExpansion(key, roundKeys);
  for (uint32_t i = 0; i < inLen; i += blockBytesLen) {
    DecryptBlock(in + i, out + i, roundKeys);
  }

  delete[] roundKeys;

  return out;
}

void AES::EncryptBlock(const uint8_t in[], uint8_t out[], const uint8_t *roundKeys) const {
  auto **state = new uint8_t *[4];
  state[0] = new uint8_t[4 * Nb];
  int i, j, round;
  for (i = 0; i < 4; i++) {
    state[i] = state[0] + Nb * i;
  }

  for (i = 0; i < 4; i++) {
    for (j = 0; j < Nb; j++) {
      state[i][j] = in[i + 4 * j];
    }
  }

  AddRoundKey(state, roundKeys, Nb);

  for (round = 1; round <= Nr - 1; round++) {
    SubBytes(state, Nb);
    ShiftRows(state, Nb);
    MixColumns(state);
    AddRoundKey(state, roundKeys + round * 4 * Nb, Nb);
  }

  SubBytes(state, Nb);
  ShiftRows(state, Nb);
  AddRoundKey(state, roundKeys + Nr * 4 * Nb, Nb);

  for (i = 0; i < 4; i++) {
    for (j = 0; j < Nb; j++) {
      out[i + 4 * j] = state[i][j];
    }
  }

  delete[] state[0];
  delete[] state;
}

void AES::DecryptBlock(const uint8_t in[], uint8_t out[], const uint8_t *roundKeys) const {
  auto **state = new uint8_t *[4];
  state[0] = new uint8_t[4 * Nb];
  for (size_t i = 0; i < 4; i++) {
    state[i] = state[0] + Nb * i;
  }

  for (size_t i = 0; i < 4; i++) {
    for (size_t j = 0; j < Nb; j++) {
      state[i][j] = in[i + 4 * j];
    }
  }

  AddRoundKey(state, roundKeys + Nr * 4 * Nb, Nb);

  for (size_t round = Nr - 1; round >= 1; round--) {
    InvSubBytes(state, Nb);
    InvShiftRows(state, Nb);
    AddRoundKey(state, roundKeys + round * 4 * Nb, Nb);
    InvMixColumns(state, Nb);
  }

  InvSubBytes(state, Nb);
  InvShiftRows(state, Nb);
  AddRoundKey(state, roundKeys, Nb);

  for (size_t i = 0; i < 4; i++) {
    for (size_t j = 0; j < Nb; j++) {
      out[i + 4 * j] = state[i][j];
    }
  }

  delete[] state[0];
  delete[] state;
}

void AES::KeyExpansion(const uint8_t key[], uint8_t w[]) const {
  auto *temp = new uint8_t[4];
  auto *rcon = new uint8_t[4];

  for (size_t i = 0; i < 4 * Nk; i++) {
    w[i] = key[i];
  }

  for (size_t i = 4 * Nk; i < 4 * Nb * (Nr + 1); i += 4) {
    temp[0] = w[i - 4 + 0];
    temp[1] = w[i - 4 + 1];
    temp[2] = w[i - 4 + 2];
    temp[3] = w[i - 4 + 3];

    if (i / 4 % Nk == 0) {
      RotWord(temp);
      SubWord(temp);
      Rcon(rcon, i / (Nk * 4u));
      XorWords(temp, rcon, temp);
    } else if (Nk > 6 && i / 4 % Nk == 4) {
      SubWord(temp);
    }

    w[i + 0] = w[i - 4 * Nk] ^ temp[0];
    w[i + 1] = w[i + 1 - 4 * Nk] ^ temp[1];
    w[i + 2] = w[i + 2 - 4 * Nk] ^ temp[2];
    w[i + 3] = w[i + 3 - 4 * Nk] ^ temp[3];
  }

  delete[] rcon;
  delete[] temp;
}

uint8_t *AES::EncryptCBC(uint8_t in[], uint32_t inLen, uint8_t key[], uint8_t *iv, uint32_t &outLen) {
  outLen = GetPaddingLength(inLen, blockBytesLen);
  uint8_t *alignIn = PaddingNulls(in, inLen, outLen);
  auto *out = new uint8_t[outLen];
  auto *block = new uint8_t[blockBytesLen];
  auto *roundKeys = new uint8_t[4 * Nb * (Nr + 1)];
  KeyExpansion(key, roundKeys);
  memcpy(block, iv, blockBytesLen);
  for (uint32_t i = 0; i < outLen; i += blockBytesLen) {
    XorBlocks(block, alignIn + i, block, blockBytesLen);
    EncryptBlock(block, out + i, roundKeys);
    memcpy(block, out + i, blockBytesLen);
  }

  delete[] block;
  delete[] alignIn;
  delete[] roundKeys;

  return out;
}

uint8_t *AES::DecryptCBC(uint8_t in[], uint32_t inLen, uint8_t key[], uint8_t *iv) {
  auto *out = new uint8_t[inLen];
  auto *block = new uint8_t[blockBytesLen];
  auto *roundKeys = new uint8_t[4 * Nb * (Nr + 1)];
  KeyExpansion(key, roundKeys);
  memcpy(block, iv, blockBytesLen);
  for (uint32_t i = 0; i < inLen; i += blockBytesLen) {
    DecryptBlock(in + i, out + i, roundKeys);
    XorBlocks(block, out + i, out + i, blockBytesLen);
    memcpy(block, in + i, blockBytesLen);
  }

  delete[] block;
  delete[] roundKeys;

  return out;
}

uint8_t *AES::EncryptCFB(uint8_t in[], uint32_t s, uint32_t inLen, uint8_t key[], uint8_t *iv, uint32_t &outLen) {
  outLen = GetPaddingLength(inLen, blockBytesLen);
  uint8_t *alignIn = PaddingNulls(in, inLen, outLen);
  auto *out = new uint8_t[outLen];
  auto *block = new uint8_t[blockBytesLen];
  auto *encryptedBlock = new uint8_t[blockBytesLen];
  auto *roundKeys = new uint8_t[4 * Nb * (Nr + 1)];
  KeyExpansion(key, roundKeys);
  memcpy(block, iv, blockBytesLen);
  for (uint32_t i = 0; i < outLen; i += blockBytesLen) {
    EncryptBlock(block, encryptedBlock, roundKeys);
    XorBlocks(alignIn + i, encryptedBlock, out + i, blockBytesLen);
    memcpy(block, block + s, blockBytesLen - s);
    memcpy(block + blockBytesLen - s, out + i, s);
  }

  delete[] block;
  delete[] encryptedBlock;
  delete[] alignIn;
  delete[] roundKeys;

  return out;
}

uint8_t *AES::DecryptCFB(uint8_t in[], uint32_t s, uint32_t inLen, uint8_t key[], uint8_t *iv) {
  auto *out = new uint8_t[inLen];
  auto *block = new uint8_t[blockBytesLen];
  auto *encryptedBlock = new uint8_t[blockBytesLen];
  auto *roundKeys = new uint8_t[4 * Nb * (Nr + 1)];
  KeyExpansion(key, roundKeys);
  memcpy(block, iv, blockBytesLen);
  for (uint32_t i = 0; i < inLen; i += blockBytesLen) {
    EncryptBlock(block, encryptedBlock, roundKeys);
    XorBlocks(in + i, encryptedBlock, out + i, blockBytesLen);
    memcpy(block, block + s, blockBytesLen - s);
    memcpy(block + blockBytesLen - s, in + i, s);
  }

  delete[] block;
  delete[] encryptedBlock;
  delete[] roundKeys;

  return out;
}

uint8_t *AES::EncryptOFB(uint8_t in[], uint32_t inLen, uint8_t key[], uint8_t *iv, uint32_t &outLen) {
  outLen = GetPaddingLength(inLen, blockBytesLen);
  uint8_t *alignIn = PaddingNulls(in, inLen, outLen);
  auto *out = new uint8_t[outLen];
  auto *block = new uint8_t[blockBytesLen];
  auto *encryptedBlock = new uint8_t[blockBytesLen];
  auto *roundKeys = new uint8_t[4 * Nb * (Nr + 1)];
  KeyExpansion(key, roundKeys);
  memcpy(block, iv, blockBytesLen);
  for (uint32_t i = 0; i < outLen; i += blockBytesLen) {
    EncryptBlock(block, encryptedBlock, roundKeys);
    memcpy(block, encryptedBlock, blockBytesLen);
    XorBlocks(alignIn + i, encryptedBlock, out + i, blockBytesLen);
  }

  delete[] block;
  delete[] encryptedBlock;
  delete[] alignIn;
  delete[] roundKeys;

  return out;
}

uint8_t *AES::DecryptOFB(uint8_t in[], uint32_t inLen, uint8_t key[], uint8_t *iv) {
  auto *out = new uint8_t[inLen];
  auto *block = new uint8_t[blockBytesLen];
  auto *encryptedBlock = new uint8_t[blockBytesLen];
  auto *roundKeys = new uint8_t[4 * Nb * (Nr + 1)];
  KeyExpansion(key, roundKeys);
  memcpy(block, iv, blockBytesLen);
  for (uint32_t i = 0; i < inLen; i += blockBytesLen) {
    EncryptBlock(block, encryptedBlock, roundKeys);
    memcpy(block, encryptedBlock, blockBytesLen);
    XorBlocks(in + i, encryptedBlock, out + i, blockBytesLen);
  }

  delete[] block;
  delete[] encryptedBlock;
  delete[] roundKeys;

  return out;
}

uint8_t *AES::EncryptCTR(uint8_t in[], uint32_t inLen, uint8_t key[], uint32_t &outLen) {
  unsigned char nonce[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
  unsigned char ctr[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  unsigned char nc[sizeof(nonce) + sizeof(ctr)];
  memcpy(nc, nonce, sizeof(nonce));

  outLen = GetPaddingLength(inLen, blockBytesLen);
  uint8_t *alignIn = PaddingNulls(in, inLen, outLen);
  auto *out = new uint8_t[outLen];
  auto *encryptedBlock = new uint8_t[blockBytesLen];
  auto *roundKeys = new uint8_t[4 * Nb * (Nr + 1)];
  KeyExpansion(key, roundKeys);

  for (uint32_t i = 0; i < outLen; i += blockBytesLen) {
    memcpy(nc + sizeof(nonce), ctr, sizeof(ctr));
    EncryptBlock(nc, encryptedBlock, roundKeys);
    XorBlocks(alignIn + i, encryptedBlock, out + i, blockBytesLen);
    memcpy(ctr, IncrementCtr(ctr, sizeof(ctr)), sizeof(ctr));
  }

  delete[] encryptedBlock;
  delete[] alignIn;
  delete[] roundKeys;

  return out;
}

uint8_t *AES::DecryptCTR(uint8_t in[], uint32_t inLen, uint8_t key[]) {
  unsigned char nonce[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
  unsigned char ctr[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  unsigned char nc[sizeof(nonce) + sizeof(ctr)];
  memcpy(nc, nonce, sizeof(nonce));
  auto *out = new uint8_t[inLen];
  auto *encryptedBlock = new uint8_t[blockBytesLen];
  auto *roundKeys = new uint8_t[4 * Nb * (Nr + 1)];
  KeyExpansion(key, roundKeys);
  for (uint32_t i = 0; i < inLen; i += blockBytesLen) {
    memcpy(nc + sizeof(nonce), ctr, sizeof(ctr));
    EncryptBlock(nc, encryptedBlock, roundKeys);
    XorBlocks(in + i, encryptedBlock, out + i, blockBytesLen);
    memcpy(ctr, IncrementCtr(ctr, sizeof(ctr)), sizeof(ctr));
  }

  delete[] encryptedBlock;
  delete[] roundKeys;

  return out;
}

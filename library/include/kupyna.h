#ifndef AES_KALYNA_KUPYNA_H
#define AES_KALYNA_KUPYNA_H

#include <cstddef>
#include <cstdint>
class Kupyna {
 public:
  explicit Kupyna(int size);
  uint8_t *Hash(uint8_t *message, size_t blocks);

  size_t GetSize() const { return message_diggest_bsize; }

 private:
  const size_t rows_count = 8;
  const size_t byte_size = 8;
  const size_t dword_size = 64;
  const size_t dword_bsize = sizeof(uint8_t);
  const size_t s_box_dimensions = 4;

  size_t message_bsize{};
  size_t block_size{};
  size_t block_bsize{};
  size_t block_dwsize{};
  size_t message_diggest_bsize{};
  size_t rounds{};

  uint8_t HighBits(uint8_t val) { return (val & 0xF0) >> 4; };
  uint8_t LowBits(uint8_t val) { return val & 0x0F; };

  void ToEndian(uint8_t *state, size_t size);

  void Init(size_t msg_bsize, const size_t blk_size, const size_t blk_bsize, size_t blk_dwsize,
            const size_t msg_diggest_bsize, const size_t rnd, const size_t st_rows);

  size_t state_rows{};

  void TMapXOR(uint8_t *state);
  void TMapAdd(uint8_t *state);
  void SubBytes(uint8_t *state);
  void ShiftRows(uint8_t *state);
  void MixColumns(uint8_t *state);
  void XORRoundKey(uint8_t *state, size_t round);
  void AddRoundKey(uint8_t *state, size_t round);
  void XORArr(uint8_t *dest, uint8_t *state, uint8_t *msg);
  void XORArr(uint8_t *dest, uint8_t *state, uint8_t *t1, uint8_t *t2);
  void MMult(uint8_t *state, const uint8_t mat[8][8]);
  uint8_t GFMult(uint8_t x, uint8_t y);
  void PadBlock(uint8_t *msg_block, uint8_t size);

};

#endif //AES_KALYNA_KUPYNA_H
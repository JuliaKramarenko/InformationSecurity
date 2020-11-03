#ifndef AES_KALYNA_KUPYNA_H
#define AES_KALYNA_KUPYNA_H

#include <cstddef>
#include <cstdint>
class Kupyna
{
 public:

  static const size_t rows_count = 8;
  static const size_t s_box_dimensions = 4;

  static const size_t b_num_512 = 8;
  static const size_t b_num_1024 = 16;
  static const size_t rounds_num_512 = 10;
  static const size_t rounds_num_1024 = 14;
  static const size_t b_byte_size = 8;
  static const size_t b_word_size = 64;

  static const size_t state_byte_size_512 = rows_count * b_num_512;
  static const size_t state_byte_size_1024 = rows_count * b_num_1024;

  static const uint8_t reduction_polinomial = 0x011d;

  Kupyna(size_t b_num);
  void Hash(uint8_t* msg, size_t msg_bit_len, uint8_t* hash_code);
//  size_t GetSize() const { return message_diggest_bsize; }

 private:
  int columns_count = 0;
  int rounds = 0;
  size_t bytes_num = 0;
  uint8_t state[b_num_1024][rows_count];
  size_t data_bytes_num = 0;
  uint8_t padding[state_byte_size_1024 * 2];
  size_t pad_bytes_num = 0;
  size_t hash_b_num = 0;

  void Init(const size_t in_rounds, const size_t in_columns, const size_t in_bytes_num, const size_t in_hash_b_num);

  void SubBytes(uint8_t state[b_num_1024][rows_count], int columns);
  void ShiftBytes(uint8_t state[b_num_1024][rows_count], int columns);
  void MixColumns(uint8_t state[b_num_1024][rows_count], int columns);
  void AddRoundConstantP(uint8_t state[b_num_1024][rows_count], int columns, int round);
  void AddRoundConstantQ(uint8_t state[b_num_1024][rows_count], int columns, int round);
  void P(uint8_t state[b_num_1024][rows_count]);
  void Q(uint8_t state[b_num_1024][rows_count]);
  uint8_t GFMult(uint8_t x, uint8_t y);
  int PadBlock(uint8_t* msg_block, size_t size);
  void Digest(uint8_t* msg_block);
  void Trunc(uint8_t* hash_code);
  void OutputTransformation(uint8_t* hash_code);


};

#endif //AES_KALYNA_KUPYNA_H
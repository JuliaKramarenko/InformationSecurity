#include "salsa20.h"
#include "gtest/gtest.h"

TEST(SALSA20, 128bit_EncryptTest) {
  uint8_t plain[64] = { 0 };
  uint8_t expected[64] = { 0 };
  uint8_t key[32] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
  uint8_t n[8] = { 101, 102, 103, 104, 105, 106, 107, 108 };
  Salsa20 salsa20(128);
  salsa20.Encrypt(key, n, 0, plain, 64);
  salsa20.Decrypt(key, n, 0, plain, 64);
  EXPECT_EQ(memcmp(plain, expected, 64), 0);
}

TEST(SALSA20, 256bit_EncryptTest) {
  uint8_t plain[64] = { 0 };
  uint8_t expected[64] = { 0 };
  uint8_t key[32] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
  uint8_t n[8] = { 101, 102, 103, 104, 105, 106, 107, 108 };
  Salsa20 salsa20(256);
  salsa20.Encrypt(key, n, 0, plain, 64);
  salsa20.Decrypt(key, n, 0, expected, 64);
  EXPECT_EQ(memcmp(plain, expected, 64), 0);
}

TEST(SALSA20, Multiblock_EncryptTest) {
  uint8_t plain[256] = { 0 };
  uint8_t expected[256] = { 0 };
  uint8_t key[16] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, };
  uint8_t n[8] = { 101, 102, 103, 104, 105, 106, 107, 108 };
  Salsa20 salsa20(128);
  salsa20.Encrypt(key, n, 0, plain, 256);
  salsa20.Decrypt(key, n, 0, plain, 256);
  EXPECT_EQ(memcmp(plain, expected, 256), 0);
}
TEST(SALSA20, RotL_Test) {
  Salsa20 salsa20(256);
  EXPECT_EQ(salsa20.RotL(0xc0a8787e, 5), 0x150f0fd8);
}

// quarterround function tests
TEST(SALSA20, QuaterRound_Test) {
  uint32_t s[4] = { 0x00000000, 0x00000000, 0x00000000, 0x00000000 };
  Salsa20 salsa20(256);
  salsa20.QuarterRound(&s[0], &s[1], &s[2], &s[3]);
//quarterround example 1 word 1
  EXPECT_EQ(s[0], 0x00000000);
//quarterround example 1 word 2
  EXPECT_EQ(s[1], 0x00000000);
//quarterround example 1 word 3
  EXPECT_EQ(s[2], 0x00000000);
//quarterround example 1 word 4
  EXPECT_EQ(s[3], 0x00000000);
}
#include "rc4.h"
#include "gtest/gtest.h"

TEST(RC4, Encrypt_key3_Test) {
  RC4 rc4{};
  unsigned char plain[] = {'P', 'l', 'a', 'i', 'n', 't', 'e', 'x', 't'};
  unsigned char key[] = {'K', 'e', 'y'};
  unsigned char expected[] = {0xbb, 0xf3, 0x16, 0xE8, 0xD9, 0x40, 0xAF, 0x0A, 0xD3};
  auto *enc = new uint8_t[sizeof(plain)];
  rc4.SetKey(key, sizeof(key));
  rc4.Encrypt(plain, enc, sizeof(plain));

  EXPECT_FALSE(memcmp(enc, expected, sizeof(plain)));
  delete[] enc;
}

TEST(RC4, Encrypt_Decrypt_key3_Test) {
  RC4 rc4{};
  unsigned char plain[] = {'P', 'l', 'a', 'i', 'n', 't', 'e', 'x', 't'};
  unsigned char key[] = {'K', 'e', 'y'};
  auto *enc = new uint8_t[sizeof(plain)];
  auto *dec = new uint8_t[sizeof(plain)];

  rc4.SetKey(key, sizeof(key));
  rc4.Encrypt(plain, enc, sizeof(plain));

  rc4.SetKey(key, sizeof(key));
  rc4.Encrypt(enc, dec, sizeof(plain));
  EXPECT_FALSE(memcmp(dec, plain, sizeof(plain)));
  delete[] enc;
  delete[] dec;
}

TEST(RC4, Encrypt_key6_Test) {
  RC4 rc4{};
  unsigned char plain[] = {'A','t','t','a','c','k',' ','a','t',' ','d','a','w','n'};
  unsigned char key[] = {'S','e','c','r','e','t'};
  unsigned char expected[] = {0x45,0xa0,0x1f,0x64,0x5f,0xc3,0x5b,0x38,0x35,0x52,0x54,0x4b,0x9b,0xf5};
  auto *enc = new uint8_t[sizeof(plain)];
  rc4.SetKey(key, sizeof(key));
  rc4.Encrypt(plain, enc, sizeof(plain));

  EXPECT_FALSE(memcmp(enc, expected, sizeof(plain)));
  delete[] enc;
}

TEST(RC4, Encrypt_Decrypt_key6_Test) {
  RC4 rc4{};
  unsigned char plain[] = {'A','t','t','a','c','k',' ','a','t',' ','d','a','w','n'};
  unsigned char key[] = {'S','e','c','r','e','t'};
  auto *enc = new uint8_t[sizeof(plain)];
  auto *dec = new uint8_t[sizeof(plain)];

  rc4.SetKey(key, sizeof(key));
  rc4.Encrypt(plain, enc, sizeof(plain));

  rc4.SetKey(key, sizeof(key));
  rc4.Encrypt(enc, dec, sizeof(plain));
  EXPECT_FALSE(memcmp(dec, plain, sizeof(plain)));
  delete[] enc;
  delete[] dec;
}

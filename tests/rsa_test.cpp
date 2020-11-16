#include "rsa.h"
#include "../rsa-helpers/helpers.h"
#include "gtest/gtest.h"
#include "gmpxx.h"
#include "gmp.h"

TEST(RSA, Encrypt_Decrypt ) {
  mpz_t p, q, phi, e, n, d, dp, dq, c, dc;
  const char msg[40] = "welcome to cryptoworld";
  int len = strlen(msg);
  mpz_init(p);
  mpz_init(q);
  mpz_init(phi);
  mpz_init(e);
  mpz_init(n);
  mpz_init(d);
  mpz_init(dp);
  mpz_init(dq);
  mpz_init(c);
  mpz_init(dc);
  RSA rsa = RSA(128, 128);
  rsa.Init( p, q, phi, n, d, e);
  int r[40];
  for (int i = 0; i < strlen(msg); i++) {
    r[i] = (int) msg[i];
  }
  int *m = r;
  mpz_t M, expected;
  mpz_init(M);
  mpz_init(expected);
  mpz_import(M, strlen(msg), 1, sizeof(m[0]), 0, 0, m);
  mpz_set(expected, M);
  rsa.Encrypt(&e, &n, &d, &c, msg);
  rsa.Decrypt(&dc, &c, &d, &n);
  EXPECT_FALSE(mpz_cmp( dc, expected));
}

TEST(RSA, Encrypt_Decrypt_CRT ) {
  mpz_t p, q, phi, e, n, d, dp, dq, c, dc;
  const char msg[40] = "Hello World!";
  int len = strlen(msg);
  mpz_init(p);
  mpz_init(q);
  mpz_init(phi);
  mpz_init(e);
  mpz_init(n);
  mpz_init(d);
  mpz_init(dp);
  mpz_init(dq);
  mpz_init(c);
  mpz_init(dc);
  RSA rsa = RSA(128, 128);
  rsa.InitCRT(p, q, phi, n, d, dp, dq, e);
  int r[40];
  for (int i = 0; i < strlen(msg); i++) {
    r[i] = (int) msg[i];
  }
  int *m = r;
  mpz_t M, expected;
  mpz_init(M);
  mpz_init(expected);
  mpz_import(M, strlen(msg), 1, sizeof(m[0]), 0, 0, m);
  mpz_set(expected, M);
  rsa.Encrypt(&e, &n, &d, &c, msg);
  rsa.DecryptCRT(&dc, &c, &dp, &dq, &p, &q, &n);
  EXPECT_FALSE(mpz_cmp( dc, expected));
}

TEST(RSA, Encrypt_Decrypt_OAEP) {
  mpz_t p, q, phi, e, n, d, dp, dq, c, dc;
  const char msg[40] = "welcome to cryptoworld";
  int len = strlen(msg);
  mpz_init(p);
  mpz_init(q);
  mpz_init(phi);
  mpz_init(e);
  mpz_init(n);
  mpz_init(d);
  mpz_init(dp);
  mpz_init(dq);
  mpz_init(c);
  mpz_init(dc);
  RSA rsa = RSA(128, 128);
  rsa.Init( p, q, phi, n, d, e);
  int NumOfBlocks = len / 16 + ((len % 16 == 0) ? 0 : 1);
  std::string msgSTR(msg);
  msgSTR.resize(NumOfBlocks * 16, (char) 0);
  std::string Xarr[NumOfBlocks];
  std::string Yarr[NumOfBlocks];
  std::string Harr[NumOfBlocks];
  std::string Garr[NumOfBlocks];
  for (int i = 0; i < NumOfBlocks; i++) {
    BlockPaddingOAEP(msgSTR.substr(i * 16, i * 16 + 15), Xarr[i], Yarr[i], Harr[i], Garr[i]);
  }
  int r[40];
  for (int i = 0; i < strlen(msg); i++) {
    r[i] = (int) msg[i];
  }
  int *m = r;
  mpz_t M, expected;
  mpz_init(M);
  mpz_init(expected);
  mpz_import(M, strlen(msg), 1, sizeof(m[0]), 0, 0, m);
  mpz_set(expected, M);
  rsa.Encrypt(&e, &n, &d, &c, msg);
  std::string RES = "";
  for (int i = 0; i < NumOfBlocks; i++) {
    std::string temp;
    BlockDepaddingOAEP(temp, Xarr[i], Yarr[i], Harr[i], Garr[i]);
    RES += temp;
  }
  rsa.Decrypt(&dc, &c, &d, &n);
  EXPECT_FALSE(mpz_cmp( dc, expected));
}

TEST(RSA, Encrypt_Decrypt_OAEP_CRT ) {
  mpz_t p, q, phi, e, n, d, dp, dq, c, dc;
  const char msg[40] = "Hello World!";
  int len = strlen(msg);
  mpz_init(p);
  mpz_init(q);
  mpz_init(phi);
  mpz_init(e);
  mpz_init(n);
  mpz_init(d);
  mpz_init(dp);
  mpz_init(dq);
  mpz_init(c);
  mpz_init(dc);
  RSA rsa = RSA(128, 128);
  rsa.InitCRT(p, q, phi, n, d, dp, dq, e);
  int NumOfBlocks = len / 16 + ((len % 16 == 0) ? 0 : 1);
  std::string msgSTR(msg);
  msgSTR.resize(NumOfBlocks * 16, (char) 0);
  std::string Xarr[NumOfBlocks];
  std::string Yarr[NumOfBlocks];
  std::string Harr[NumOfBlocks];
  std::string Garr[NumOfBlocks];
  for (int i = 0; i < NumOfBlocks; i++) {
    BlockPaddingOAEP(msgSTR.substr(i * 16, i * 16 + 15), Xarr[i], Yarr[i], Harr[i], Garr[i]);
  }
  int r[40];
  for (int i = 0; i < strlen(msg); i++) {
    r[i] = (int) msg[i];
  }
  int *m = r;
  mpz_t M, expected;
  mpz_init(M);
  mpz_init(expected);
  mpz_import(M, strlen(msg), 1, sizeof(m[0]), 0, 0, m);
  mpz_set(expected, M);
  rsa.Encrypt(&e, &n, &d, &c, msg);
    std::string RES = "";
    for (int i = 0; i < NumOfBlocks; i++) {
      std::string temp;
      BlockDepaddingOAEP(temp, Xarr[i], Yarr[i], Harr[i], Garr[i]);
      RES += temp;
    }
  rsa.DecryptCRT(&dc, &c, &dp, &dq, &p, &q, &n);
  EXPECT_FALSE(mpz_cmp( dc, expected));
  }
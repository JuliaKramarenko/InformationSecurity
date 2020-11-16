#include <time.h>
#include <sha256.h>
#include "helpers.h"
#include <iostream>
#include <chrono>

static gmp_randclass *prng = NULL;

bool IsPrime(const mpz_class &n, const size_t rounds) {
  return MillerRabinTest(n > 0 ? n : -n, rounds);
}

bool MillerRabinTest(const mpz_class &n, const size_t rounds) {
  // Treat n==1, 2, 3 as a primes
  if (n == 1 || n == 2 || n == 3)
    return true;

  // Treat negative numbers in the frontend
  if (n <= 0)
    return false;

  // Even numbers larger than two cannot be prime
  if ((n & 1) == 0)
    return false;

  // Write n-1 as d*2^s by factoring powers of 2 from n-1
  size_t s = 0;
  {
    mpz_class m = n - 1;
    while ((m & 1) == 0) {
      ++s;
      m >>= 1;
    }
  }
  const mpz_class d = (n - 1) / (mpz_class(1) << s);

  for (size_t i = 0; i < rounds; ++i) {
    const mpz_class a = RandINT(2, n - 2);
    mpz_class x = PowMOD(a, d, n);

    if (x == 1 || x == (n - 1))
      continue;

    for (size_t r = 0; r < (s - 1); ++r) {
      x = PowMOD(x, 2, n);
      if (x == 1) {
        // Definitely not a prime
        return false;
      }
      if (x == n - 1)
        break;
    }

    if (x != (n - 1)) {
      // Definitely not a prime
      return false;
    }
  }
  return true;
}

mpz_class PowMOD(mpz_class a, mpz_class x, const mpz_class &n) {
  mpz_class r = 1;

  while (x > 0) {
    if ((x & 1) == 1) {
      r = a * r % n;
    }
    x >>= 1;
    a = a * a % n;
  }

  return r;
}

mpz_class RandINT(const mpz_class &lowest, const mpz_class &highest) {
  if (!prng) {
    // Default number of bytes to read for seed
    InitSeed(256 / 8);
  }

  if (lowest == highest)
    return lowest;

  return prng->get_z_range(highest - lowest + 1) + lowest;
}

void DeletePRNG() {
  delete prng;
  prng = NULL;
}

int InitSeed(const size_t bytes) {
  if (!prng)
    prng = new gmp_randclass(gmp_randinit_default);

  if (bytes > 0) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) {
      // Fall-through to use current time as seed
    } else {
      mpz_class seed = 0;
      for (size_t i = 0; i < bytes; ++i) {
        int n = fgetc(f);
        seed = (seed << 8) | n;
      }

      fclose(f);
      prng->seed(seed);
      return bytes;
    }
  }

  // Just seed with the current time
  prng->seed(time(NULL));
  return 0;
}

void BlockPaddingOAEP(const std::string &msg, std::string &X, std::string &Y, std::string &H, std::string &G) {
  //msg.length() must be 16 as using sha 256 bits
  //std::cout << "Padding starts\n";
  //std::cout << msg;
  //std::cout
   //   << "XOR the string with  Sha256(k0) where k0 = 0000000000000000 will get m which is the message will be encrypted by RSA\n";
  std::string r = "0000000000000000\n";
  SHA256 sha256 = SHA256();
  G = sha256.Hash(r);

  //std::cout << "the value from Sha(r) is G = " << G << "\n";
  X = "";
  for (int i = 0; i < msg.length(); i++) {
    X += (char) (msg[i] ^ G[i % G.length()]);
  }

  //std::cout << X;
  H = sha256.Hash(X);
  //std::cout << "getting the Y value by XOR k0 pre hash with sha256(m)\n";
  Y = "";
  for (int i = 0; i < r.length(); i++) {
    Y += (char) (r[i] ^ H[i % H.length()]);
  }
  //std::cout << Y;
  //std::cout << "\n-------padding is over ! time to RSA-------\n";
}

void BlockDepaddingOAEP(std::string &msg,
                        const std::string &X,
                        const std::string &Y,
                        const std::string &H,
                        const std::string &G) {
  //std::cout << " XOR  Y with sha256(hh) we will get k0\n";
  std::string r = "";
  for (int i = 0; i < Y.length(); i++) {
    r += (char) (Y[i] ^ H[i % H.length()]);
  }
  //std::cout << "value of r =" << r;

  //std::cout << " XOR  X with G we will get m padded\n";
  msg = "";
  for (int i = 0; i < X.length(); i++) {
    msg += (char) (X[i] ^ G[i % G.length()]);
  }
  //std::cout << "value of m padded =" << msg << "\n";
}
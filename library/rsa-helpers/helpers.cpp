#include <time.h>
#include "helpers.h"

static gmp_randclass *prng = NULL;

bool IsPrime(const mpz_class& n, const size_t rounds){
  return MillerRabinTest(n > 0 ? n : -n, rounds);
}

bool MillerRabinTest(const mpz_class& n, const size_t rounds){
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

    if (x ==1 || x == (n - 1))
      continue;

    for (size_t r = 0; r < (s-1); ++r) {
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

  // Might be prime
  return true;
}

mpz_class PowMOD(mpz_class a, mpz_class x, const mpz_class& n){
  mpz_class r = 1;

  while (x > 0) {
    if ((x & 1) == 1) {
      r = a*r % n;
    }
    x >>= 1;
    a = a*a % n;
  }

  return r;
}

mpz_class RandINT(const mpz_class& lowest, const mpz_class& highest){
  if (!prng) {
    // Default number of bytes to read for seed
    InitSeed(256 / 8);
  }

  if ( lowest == highest )
    return lowest;

  return prng->get_z_range(highest - lowest + 1) + lowest;
}

void DeletePRNG(){
  delete prng;
  prng = NULL;
}

int InitSeed(const size_t bytes){
  if (!prng)
    prng = new gmp_randclass(gmp_randinit_default);

  if (bytes > 0) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) {
      perror("/dev/urandom");
      // Fall-through to use current time as seed
    } else {
      mpz_class seed = 0;
      for ( size_t i = 0; i < bytes; ++i ) {
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
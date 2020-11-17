#ifndef AES_KALYNA_HELPERS_H
#define AES_KALYNA_HELPERS_H

#include <gmpxx.h>
#include <stdint.h>

bool IsPrime(const mpz_class& n, const size_t rounds);
bool MillerRabinTest(const mpz_class& n, const size_t rounds);
extern "C" int InitSeed(const size_t bytes);
mpz_class PowMOD(mpz_class a, mpz_class x, const mpz_class& n);
mpz_class RandINT(const mpz_class& lowest, const mpz_class& highest);
void DeletePRNG();

#endif //AES_KALYNA_HELPERS_H

#ifndef AES_KALYNA_GF2_H
#define AES_KALYNA_GF2_H

#include <iosfwd>
#include <cstdint>
#include <vector>
#include <bitset>
#include "ecc.h"
class GF
{
 public:
  static mpz_class ConvertToFx(std::vector<mpz_class> powers);
  static mpz_class M(mpz_class f);
  static mpz_class Add(mpz_class a, mpz_class b);
  static mpz_class Mult(mpz_class a, mpz_class b, mpz_class f);
  static mpz_class Div(mpz_class a, mpz_class b, mpz_class f);
  static mpz_class ModPow(mpz_class a, mpz_class b, mpz_class f);
  static mpz_class Square(mpz_class a, mpz_class f);
  static mpz_class Sqrt(mpz_class a, mpz_class f);
  static mpz_class Inv(mpz_class a, mpz_class f);
  static mpz_class Trace(mpz_class a, mpz_class m, mpz_class t);
  static mpz_class HalfTrace(mpz_class a, mpz_class m, mpz_class t);
};
#endif //AES_KALYNA_GF2_H

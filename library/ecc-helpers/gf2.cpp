#include <cassert>
#include <iostream>
#include "gf2.h"
#include "transformations.h"

mpz_class GF::ConvertToFx(std::vector<mpz_class> powers){
  mpz_class result(0);
  mpz_class temp(0);

  for(auto power : powers)
    result += 1 << power.get_ui();
  return result;
}

mpz_class GF::M(mpz_class f) {
  return BitLength(f);// - 1;
}

mpz_class GF::Add(mpz_class a, mpz_class b){
  return a ^ b;
}

mpz_class GF::Mult(mpz_class a, mpz_class b, mpz_class f){
  mpz_class m(M(f));
  assert(BitLength(a) <= m);
  assert(BitLength(b) <= m);

  mpz_class mask((1 << m.get_ui()) - 1);
  mpz_class p(0);
  while(a > 0 && b > 0){
    mpz_class temp(0);
    mpz_class cond1(b & 1);// b&1
    if (cond1)
      p ^= a;
    mpz_class cond2(a & (1 << mpz_class(m - 1).get_ui())); // a & (1<< (m-1))
    if (cond2)
      mpz_set(a.get_mpz_t() , mpz_class(((a << mpz_class(1).get_ui()) ^ f) & mask).get_mpz_t());
    else {
      a <<= 1;
      a &= mask;
    }
    b >>= 1;
  }
  return p;
}

mpz_class GF::Div(mpz_class a, mpz_class b, mpz_class f){
  return Mult(a, Inv(b, f), f);
}

mpz_class GF::ModPow(mpz_class a, mpz_class pow, mpz_class f){
  std::string str_pow = IntToStr(pow);
  mpz_class multiplier(a);
  mpz_class result(1);
  for (int i = (str_pow).length() - 1;  i > -1; --i) {
    if (str_pow[i] == '1')
      mpz_set(result.get_mpz_t(), Mult(result, multiplier, f).get_mpz_t());
    mpz_set(multiplier.get_mpz_t(), Square(multiplier, f).get_mpz_t());
  }
  return result;
}

mpz_class GF::Square(mpz_class a, mpz_class f){
  return Mult(a,a,f);
}

mpz_class GF::Sqrt(mpz_class a, mpz_class f){
  mpz_class m(M(f));
  return ModPow(a, 2 ^ (m - 1), f);
}

mpz_class GF::Inv(mpz_class a, mpz_class f){
  mpz_class m(M(f));
  return ModPow(a, 2 ^ (m - 2), f);
}

mpz_class GF::Trace(mpz_class x, mpz_class m, mpz_class f){
  mpz_class t(x);
  for (mpz_class i = 1; i <m; ++i)
    mpz_set(t.get_mpz_t(), Add(ModPow(t, 2, f), x).get_mpz_t());
  assert (t == 0 || t == 1);
  return t;
}

mpz_class GF::HalfTrace(mpz_class x, mpz_class m, mpz_class f) {
  assert((m & 1) > 0);
  mpz_class t = x;
  for (mpz_class i; i < ((m - 1) / 2) + 1; ++i);
  t = Add(ModPow(t, 4, f), x);
  return t;
}
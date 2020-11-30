#include "transformations.h"
std::string IntToStr(mpz_class num) {
  char* temp = mpz_get_str(NULL ,2, num.get_mpz_t());
  return std::string(temp);
  //return tempStr.substr(0, tempStr.length());
}

mpz_class StrToInt(std::string num) {
  return mpz_class(num, 2);
}

mpz_class BitLength(const mpz_class& number)
{
  mpz_class bits(0), x;
  mpz_init_set(x.get_mpz_t(), number.get_mpz_t());
  mpz_set( x.get_mpz_t(), (x < 0)? mpz_class(-x).get_mpz_t() : x.get_mpz_t());
  for(; x != 0 && bits < number.get_mpz_t()->_mp_size; bits++)
    x >>= mpz_class(1).get_ui();
  return bits;
}

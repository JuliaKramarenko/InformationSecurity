#ifndef AES_KALYNA_ECC_H
#define AES_KALYNA_ECC_H
#include <gmpxx.h>

class EllipticCurve;
class Point;

class ECC{
 private:
  mpz_class _A, _B,_m, _f, _n, _Ln, _d, _e, _Fe, _LD;
  EllipticCurve* _curve;
  Point* _P;
  Point* _Q;

 public:
  ECC(mpz_class A, mpz_class B, mpz_class m, mpz_class n, EllipticCurve* curve);
  std::tuple<unsigned char*, size_t, std::string> Sign(unsigned char* bytes, size_t size);
  bool ValidateSignature(std::tuple<unsigned char*, size_t, std::string> signature);
  mpz_class TransformToFieldEl(std::string bytes);
  mpz_class TransformToInt(mpz_class element);
  std::string TransformToSignature(mpz_class r, mpz_class s);
  std::pair<mpz_class, mpz_class> TransformToNumPair(std::string D);
  Point CalcBasePoint();
  mpz_class GetPrivateKey();
  Point GetPublicKey();
  std::pair<mpz_class, mpz_class> CalcPreSignature();
  mpz_class CalcRandNum();
  std::string ToNumBits(std::string s);
};

#endif //AES_KALYNA_ECC_H

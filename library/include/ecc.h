#ifndef AES_KALYNA_ECC_H
#define AES_KALYNA_ECC_H
#include <gmpxx.h>
#include <vector>

class EllipticCurve;
class Point;

class ECC{
 private:
  mpz_class _A, _B, _f, _n, _d, _e, _Fe;
  unsigned int _m, _Ln, _LD;
  EllipticCurve* _curve;
  Point* _P;
  Point* _Q;

 public:
  ECC(mpz_class A, mpz_class B, unsigned int m, mpz_class n, std::vector<mpz_class> powers);
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

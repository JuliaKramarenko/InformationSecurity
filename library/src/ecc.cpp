#include <iostream>
#include <sha256.h>
#include <tuple>
#include <cmath>
#include "ecc.h"
#include "../ecc-helpers/gf2.h"
#include "../ecc-helpers/curve.h"
#include "../ecc-helpers/transformations.h"

ECC::ECC(mpz_class A, mpz_class B, unsigned int m, mpz_class n, std::vector<mpz_class> powers){
  mpz_init_set(_A.get_mpz_t(), A.get_mpz_t());
  mpz_init_set(_B.get_mpz_t(), B.get_mpz_t());
  _m = m;
  mpz_init_set(_n.get_mpz_t(), n.get_mpz_t());
  _curve = new EllipticCurve(A, B, m, powers);
  _Ln = BitLength(_n);
  _f = _curve->getF();
  _P = new Point(CalcBasePoint());

  mpz_init_set(_d.get_mpz_t(), GetPrivateKey().get_mpz_t()); // private key
  _Q = new Point(GetPublicKey()); // public key
  auto [e, Fe] = CalcPreSignature(); // e and pre-signature
  mpz_init_set(_e.get_mpz_t(), e.get_mpz_t());
  mpz_init_set(_Fe.get_mpz_t(), Fe.get_mpz_t());
  _LD = std::ceil((2 * _Ln)/ 16.f) *16;
}

std::tuple<unsigned char*, size_t, std::string> ECC::Sign(unsigned char* bytes, size_t size){
  std::cout<<"\nStarted signing "<< bytes;
  SHA256 sha256;
  std::string T_hash = sha256.Hash(bytes, size);
  std::cout<<"\n T_hash = " << T_hash;
  mpz_class h (TransformToFieldEl(T_hash));
  std::cout<<"\n h = " << h;
  if ( h == 0)
    h = 1;
  mpz_class y (GF::Mult(_Fe, h, _f));
  std::cout<<"\ny = " << y;
  mpz_class r (TransformToInt(y));
  std::cout<<"\nr = " << r;
  if (r == 0)
    throw std::invalid_argument("invalid r: 0");

  mpz_class s ((_e + _d * r) % _n);
  std::cout<<"\ns = " << s;
  if (s == 0)
    throw std::invalid_argument("invalid s: 0");
  std::string D = TransformToSignature(r, s);
  std::cout<<"\nD = " << D;

  return std::tuple(bytes, size, D);
}

bool ECC::ValidateSignature(std::tuple<unsigned char*, size_t, std::string> signature){
  auto [T, size, D] = signature;
  std::cout<<"\nVerifying signature for " << T;
  SHA256 sha;
  std::string T_hash = sha.Hash(T, size);
  std::cout<<"\nD =" << D;
  std::cout<<"\nT_hash =" << T_hash;
  mpz_class h(TransformToFieldEl(T_hash));
  std::cout<<"\nh = " << h;
  if (h == 0)
    h = 1;
  auto [ r, s ] = TransformToNumPair(D);
  std::cout<<"\nr = " << r;
  std::cout<<"\ns = " << s;
  if (!(0 < BitLength(r) < _Ln))
    return false;
  if (!(0 < BitLength(s) < _Ln))
    return false;
  Point R = _curve->AddPoints(_curve->MultPoint(*_P, s),_curve->MultPoint(*_Q, r));
  std::cout<<"\nR = " << R;
  mpz_class y (GF::Mult(h, R.getX(), _curve->getF()));
  std::cout<<"\ny = " << y;
  mpz_class r_prime (TransformToInt(y));
  std::cout<<"\nr_prime = " << r_prime;
  return r == r_prime;
}

mpz_class ECC::TransformToFieldEl(std::string bytes){
  mpz_class number(bytes, 16);
  return number & _curve->getMask();
}

mpz_class ECC::TransformToInt(mpz_class element){
  if (element == 0)
    return 1;
  mpz_class shift(0);
  mpz_mul_2exp(shift.get_mpz_t(), mpz_class(1).get_mpz_t(), _Ln - 1);
  mpz_class mask (shift - 1);
#if DEBUG
  std::cout<< "\nshift = " << shift;
    std::cout<< "\nmask = " << mask;
#endif //DEBUG
  return element & mask;
}

std::string ECC::TransformToSignature(mpz_class r, mpz_class s){
  unsigned int l = _LD/2;
  unsigned int  l_r  = BitLength(r);
  unsigned int  l_s = BitLength(s);
  std::string R = "";
  for(unsigned int i = 0; i < (l - l_r); ++i)
    R +='0';
  R += IntToStr(r);
  std::string S = "";
  for(unsigned int  i = 0; i < (l - l_s); ++i)
    S +='0';
  S += IntToStr(s);
  return S + R;
}

std::pair<mpz_class, mpz_class> ECC::TransformToNumPair(std::string D){
  unsigned int l = _LD/ 2;
  std::string S = D.substr(0, l);
  std::string R = D.substr(l, D.length());
  std::string s_bits = ToNumBits(S);
  std::string r_bits = ToNumBits(R);
  return std::pair(StrToInt(r_bits), StrToInt(s_bits));
}

Point ECC::CalcBasePoint(){
  std::cout<<"\nStarted calculating base point";
  unsigned int i = 0;
  while (1) {
    std::cout<<"\nattempt: "<< i;
    i+=1;
    Point candidate = _curve->GenPoint();
    std::cout<< "\ncandidate " << candidate;
    Point multiplied = _curve->MultPoint(candidate, _n);
    std::cout<< "\nmultiplied" << multiplied;
    if (multiplied == _curve->getZero()) {
      std::cout << "\n P =" << candidate;
      return candidate;
    }
  }
}

mpz_class ECC::GetPrivateKey() {
  std::cout << "\nStarted calculating private key";
  while (1) {
    mpz_class candidate = CalcRandNum();
    if (candidate != 0) {
      std::cout << "\n d = " << candidate;
      return candidate;
    }
  }
}

Point ECC::GetPublicKey(){
  std::cout<<"\nStarted calculating public key";
  Point result = _curve->NegPoint(_curve->MultPoint(*_P, _d));
  std::cout<< "\nQ = " << result;
  return result;
}

std::pair<mpz_class, mpz_class> ECC::CalcPreSignature(){
  std::cout<<"\nStarted calculating pre-signature";
  while (1) {
    mpz_class e = CalcRandNum();
    Point candidate = _curve->MultPoint(*_P, e);
    if (candidate.getX() != 0)
    {
      std::cout<<"\ne = " << e;
      std::cout<<"\nF_e = " << candidate.getX();
      std::cout<<"\nF_e point "<< candidate;
      return std::pair(e, candidate.getX());
    }
  }
}

mpz_class ECC::CalcRandNum(){
  unsigned int length = std::ceil((_Ln - 1)/8.f);
  mpz_class rand(0);
  mpz_random(rand.get_mpz_t(), length);
  mpz_class mask = (mpz_class(1) << (_Ln - 1)) - 1;
  return rand & mask;
}

std::string ECC::ToNumBits(std::string s){
  uint32_t first_one_index = s.find('1');
  return s.substr(first_one_index, s.length());
}

#include <iostream>
#include <sha256.h>
#include <tuple>
#include "ecc.h"
#include "../ecc-helpers/gf2.h"
#include "../ecc-helpers/curve.h"
#include "../rsa-helpers/helpers.h"
#include "../ecc-helpers/transformations.h"

ECC::ECC(mpz_class A, mpz_class B, mpz_class m, mpz_class n, EllipticCurve* curve){
  mpz_init_set(_A.get_mpz_t(), A.get_mpz_t());
  mpz_init_set(_B.get_mpz_t(), B.get_mpz_t());
  mpz_init_set(_m.get_mpz_t(), m.get_mpz_t());
  mpz_init_set(_n.get_mpz_t(), n.get_mpz_t());
  mpz_init_set(_Ln.get_mpz_t(),BitLength(_n).get_mpz_t());
  _curve = curve;
  _P = new Point(CalcBasePoint());
  _f = _curve->getF();
  mpz_init_set(_d.get_mpz_t(), GetPrivateKey().get_mpz_t()); // private key
  _Q = new Point(GetPublicKey()); // public key
  auto [e, Fe] = CalcPreSignature(); // e and pre-signature
  mpz_init_set(_e.get_mpz_t(), e.get_mpz_t());
  mpz_init_set(_Fe.get_mpz_t(), Fe.get_mpz_t());
  mpz_class length(0);
  mpz_cdiv_r(length.get_mpz_t(), mpz_class(2*_Ln).get_mpz_t(), mpz_class(16).get_mpz_t());
  _LD = length * 16;
}

std::tuple<unsigned char*, size_t, std::string> ECC::Sign(unsigned char* bytes, size_t size){
  SHA256 sha256;
  std::string T_hash = sha256.Hash(bytes, size);
  mpz_class h = TransformToFieldEl(T_hash);
  if ( h == 0)
    h = 1;
  mpz_class y = GF::Mult(_Fe, h, _f);
  mpz_class r = TransformToInt(y);
  if (r == 0)
    throw ("invalid r: 0");

  mpz_class s = (_e + _d * r) % _n;
  if (s == 0)
    throw ("invalid s: 0");
  std::string D = TransformToSignature(r, s);

  std::cout<<"\n Signing = " << bytes;
  std::cout<<"\n T_hash = " << T_hash;
  std::cout<<"\n h = " << h;
  std::cout<<"\n y = " << y;
  std::cout<<"\n r = " << r;
  std::cout<<"\n s = " << s;
  std::cout<<"\n D = " << D;
  return std::tuple(bytes, size, D);
}

std::pair<mpz_class, mpz_class> ECC::TransformToNumPair(std::string D){
  mpz_class l = _LD; // 2
  std::string S = D.substr(0, l.get_ui());
  std::string R = D.substr(l.get_ui(), D.length());
  std::string s_bits = ToNumBits(S);
  std::string r_bits = ToNumBits(R);
  return std::pair(StrToInt(r_bits), StrToInt(s_bits));
}
bool ECC::ValidateSignature(std::tuple<unsigned char*, size_t, std::string> signature){
  auto [T, size, D] = signature;
  SHA256 sha;
  std::string T_hash = sha.Hash(T, size);
  mpz_class h = TransformToFieldEl(T_hash);
  if (h == 0)
    h = 1;
  auto [ r, s ] = TransformToNumPair(D);
  if (!(0 < BitLength(r) < _Ln))
    return false;
  if (!(0 < BitLength(s) < _Ln))
    return false;
  Point R = _curve->AddPoints(_curve->MultPoint(*_P, s),_curve->MultPoint(*_Q, r));
  mpz_class y = GF::Mult(h, R.getX(), _curve->getF());
  mpz_class r_prime = TransformToInt(y);

  std::cout<<"\n Verifying signature for " << T;
  std::cout<<"\n D =" << D;
  std::cout<<"\n T_hash =" << T_hash;
  std::cout<<"\n h = " << h;
  std::cout<<"\n r = " << r;
  std::cout<<"\n s = " << s;
  std::cout<<"\n R = " << R;
  std::cout<<"\n y = " << y;
  std::cout<<"\n r_prime = " << r_prime;
  return r == r_prime;
}

mpz_class ECC::TransformToFieldEl(std::string bytes){
  mpz_class number(bytes);
  return number & _curve->getMask();
}

mpz_class ECC::TransformToInt(mpz_class element){
  if (element == 0)
    return 1;
  mpz_class mask = (1 << mpz_class(_Ln - 1).get_ui()) - 1;
  return element & mask;
}

std::string ECC::TransformToSignature(mpz_class r, mpz_class s){
  mpz_class l = _LD; // 2
  mpz_class l_r = BitLength(r);
  mpz_class l_s = BitLength(s);
  std::string R = "";
  for(mpz_class i = 0; i < l - l_r; ++i)
    R +='0';
  R += IntToStr(r);
  std::string S = "";
  for(mpz_class i = 0; i < l - l_s; ++i)
    S +='0';
  S += IntToStr(s);
  return S + R;
}

Point ECC::CalcBasePoint(){
  std::cout<<"\nStarted calculating base point";
  mpz_class i(0);
  while (1) {
    std::cout<<"\nattempt: "<< i;
    i = i + 1;
    Point candidate = _curve->GenPoint();
    std::cout<< "\n candidate " << candidate;
    Point multiplied = _curve->MultPoint(candidate, _n);
    std::cout<< "\n multiplied" << multiplied;
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
  mpz_class length(0);
  mpz_cdiv_r(length.get_mpz_t(), mpz_class(_Ln - 1).get_mpz_t(), mpz_class(8).get_mpz_t());
  mpz_class R = RandINT(0, length);
  mpz_class mask = (1 << mpz_class((_Ln - 1)).get_ui()) - 1;
  return R & mask;
}

std::string ECC::ToNumBits(std::string s){
  uint32_t first_one_index = s.find('1');
  return s.substr(first_one_index, s.length());
}

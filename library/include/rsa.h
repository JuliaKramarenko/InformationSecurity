#ifndef AES_KALYNA_RSA_H
#define AES_KALYNA_RSA_H
#include <gmp.h>
class RSA {
 public:
  void InitCRT(mpz_t& p, mpz_t& q, mpz_t& phi, mpz_t& n, mpz_t& d,  mpz_t& dp, mpz_t& dq, mpz_t& e);
  void Encrypt(mpz_t* e, mpz_t* n, mpz_t* d, mpz_t* c, char[]);
  void DecryptCRT(mpz_t* m, mpz_t* c, mpz_t* dp, mpz_t* dq, mpz_t* p, mpz_t* q, mpz_t* n);
  void Init(mpz_t& p, mpz_t& q, mpz_t& phi, mpz_t& n, mpz_t& d, mpz_t& e);
  void Decrypt(mpz_t* m, mpz_t* c, mpz_t* d, mpz_t* n);

 private:
  void generatePrimes(mpz_t* p, mpz_t* q);
  void computeNandF(mpz_t* q, mpz_t* p, mpz_t *phi, mpz_t* n);
  void generateE(mpz_t* phi, mpz_t* e);
  //void encrFile(mpz_t e, mpz_t n, mpz_t d, mpz_t c);

  gmp_randstate_t stat;

};
#endif //AES_KALYNA_RSA_H

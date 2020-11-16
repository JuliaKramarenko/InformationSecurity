#include "rsa.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <math.h>
#include <sys/types.h>
#include <chrono>
#include "gmpxx.h"
#include "../rsa-helpers/helpers.h"

void RSA::generatePrimes(mpz_t *p, mpz_t *q) {
  auto const &before_mr = std::chrono::high_resolution_clock::now();

  bool primetest = false;

  long sd = 0;
  mpz_t seed;
  gmp_randinit(stat, GMP_RAND_ALG_LC, 120);
  mpz_init(seed);
  srand((unsigned) getpid());
  sd = rand();
  mpz_set_ui(seed, sd);
  gmp_randseed(stat, seed);

  mpz_urandomb(*p, stat, p_length * 8);

  primetest = IsPrime(mpz_class(*p), 10);

  if (primetest) {
    //printf("p is prime\n");
  } else {
    //printf("p wasnt prime,choose next prime\n");
    mpz_nextprime(*p, *p);
  }

  mpz_urandomb(*q, stat, q_length * 8);
  primetest = IsPrime(mpz_class(*q), 10);
  if (primetest) {
    // printf("q is prime\n");
  } else {
    // printf("p wasnt prime,choose next prime\n");
    mpz_nextprime(*q, *q);
  }
  auto const &after_mr = std::chrono::high_resolution_clock::now();
  size_t const microseconds_in_a_second = 1000 * 1000;
  printf(
      "Miller-Rabin took %.6lfs\n",
      static_cast<double>(std::chrono::duration_cast<std::chrono::microseconds>(after_mr - before_mr).count())
      / static_cast<double>(microseconds_in_a_second));

  /*printf("p and q generated!!\n");
  printf("p = ");
  mpz_out_str(stdout, 10, *p);
  printf("\n");
  printf("q = ");
  mpz_out_str(stdout, 10, *q);
  printf("\n------------------------------------------------------------------------------------------\n");
  //mpz_clear(seed);*/
  return;
}

void RSA::computeNandF(mpz_t *q, mpz_t *p, mpz_t *phi, mpz_t *n) {

  mpz_t temp1, temp2;
  mpz_init(temp1);
  mpz_init(temp2);
  //n=p*q
  mpz_mul(*n, *q, *p);
  mpz_sub_ui(temp1, *q, 1); //temp1=q-1
  mpz_sub_ui(temp2, *p, 1); //temp2=p-1
  //φ=(p-1)(q-1)
  mpz_mul(*phi, temp1, temp2);
  /*printf("phi and n generated!!\n");
  printf(" n= ");
  mpz_out_str(stdout, 10, *n);
  printf("\n");
  printf("phi = ");
  mpz_out_str(stdout, 10, *phi);
  printf("\n------------------------------------------------------------------------------------------\n");*/
}

void RSA::generateE(mpz_t *phi, mpz_t *e) {
  mpz_t temp, seed;
  mpz_init(seed);
  mpz_init(temp);
  long sd = 0;
  gmp_randinit_default(stat);
  srand((unsigned) getpid());
  sd = rand();
  mpz_set_ui(seed, sd);
  gmp_randseed(stat, seed);

  do {
    mpz_set(temp, *phi);
    mpz_add_ui(temp, temp, 1);
    // temp = phi + 1
    mpz_urandomm(*e, stat, temp);
    // temp=gcd(e, phi)
    mpz_gcd(temp, *phi, *e);
    // gmp_printf("temp %Zd\n", temp);
  } while (mpz_cmp_ui(temp, 1) != 0);
  //printf("e generated \n e = ");
  //mpz_out_str(stdout, 10, *e);
  mpz_clear(seed);
  mpz_clear(temp);
  //printf("\n------------------------------------------------------------------------------------------\n");

}

void RSA::Init(mpz_t &p, mpz_t &q, mpz_t &phi, mpz_t &n, mpz_t &d, mpz_t &e) {
  // RSA algorithm
  generatePrimes(&p, &q);
  computeNandF(&q, &p, &phi, &n);
  generateE(&phi, &e);
  // save keys
  SavePQ(&p, &q);
  // extended Euclidean
  mpz_invert(d, e, phi);
  //printf("d = ");
  //mpz_out_str(stdout, 10, d);
  //printf("\n------------------------------------------------------------------------------------------\n");
}

void RSA::InitCRT(mpz_t &p, mpz_t &q, mpz_t &phi, mpz_t &n, mpz_t &d, mpz_t &dp, mpz_t &dq, mpz_t &e) {
  Init(p, q, phi, n, d, e);

  mpz_class temp;
  temp = mpz_class(p) - 1;
  mpz_invert(dp, e, temp.get_mpz_t());

  //printf("dp = ");
  //mpz_out_str(stdout, 10, dp);
  //printf("\n");

  temp = mpz_class(q) - 1;
  mpz_invert(dq, e, temp.get_mpz_t());
  //mpz_out_str(stdout, 10, dq);
  //printf("\n------------------------------------------------------------------------------------------\n");
}

void RSA::Encrypt(mpz_t *e, mpz_t *n, mpz_t *d, mpz_t *c, const char *msg) {

  int r[40];
  for (int i = 0; i < strlen(msg); i++) {
    r[i] = (int) msg[i];
  }

  int *m = r;
  mpz_t M;
  mpz_init(M);
  mpz_import(M, strlen(msg), 1, sizeof(m[0]), 0, 0, m);
  printf("message as int before encryption  = ");
  mpz_out_str(stdout, 10, M);
  printf("\n");

  mpz_powm(*c, M, *e, *n);
}

void RSA::Decrypt(mpz_t *m, mpz_t *c, mpz_t *d, mpz_t *n) {
  mpz_powm(*m, *c, *d, *n);
}

void RSA::DecryptCRT(mpz_t *m, mpz_t *c, mpz_t *dp, mpz_t *dq, mpz_t *p, mpz_t *q, mpz_t *n) {

  mpz_t mp, mq;
  mpz_init(mp);
  mpz_init(mq);

  mpz_powm(mp, *c, *dp, *p); // mp <- C^{dp} mod p
  mpz_powm(mq, *c, *dq, *q); // mq <- C^{dq} mod q

  mpz_t inv_q;
  mpz_init(inv_q);
  mpz_invert(inv_q, *q, *p);
  //printf("q inverted = ");
  //mpz_out_str(stdout, 10, inv_q);

  mpz_sub(mp, mp, mq); // mp - mq
  mpz_mul(mp, mp, inv_q); // (mp - mq) * inv_q
  mpz_mod(mp, mp, *p); // ((mp - mq) * inv_q) % p
  mpz_mul(mp, mp, *q); // (((mp - mq) * inv_q) % p)*q
  mpz_add(mp, mp, mq);// mq + (((mp - mq) * inv_q) % p)*q
  mpz_set(*m, mp); //m = mp;

}

void RSA::SavePQ(mpz_t *p, mpz_t *q) {
  // save p
  {
    FILE *output = fopen("p-key.txt", "w");
    mpz_out_str(output, 10, *p);
    fclose(output);
  }
  // save q
  {
    FILE *output = fopen("q-key.txt", "w");
    mpz_out_str(output, 10, *q);
    fclose(output);
  }
}
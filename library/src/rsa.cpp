#include "rsa.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <math.h>
#include <sys/types.h>
#include "gmp.h"
#include "../rsa-helpers/helpers.h"

void RSA::generatePrimes(mpz_t* p, mpz_t* q) {

  bool primetest;
  long sd = 0;
  mpz_t seed;
  gmp_randinit(stat, GMP_RAND_ALG_LC, 120);
  mpz_init(seed);
  srand((unsigned) getpid());
  sd = rand();
  mpz_set_ui(seed, sd);
  gmp_randseed(stat, seed);


  mpz_urandomb(*p, stat, 512);
  primetest = IsPrime(mpz_class(*p), 10);
  if (primetest) {
    printf("p is prime\n");
  } else {
    //printf("p wasnt prime,choose next prime\n");
    mpz_nextprime(*p, *p);
  }

  mpz_urandomb(*q, stat, 512);
  primetest = IsPrime(mpz_class(*q), 10);
  if (primetest) {
    // printf("q is prime\n");
  } else {
    // printf("p wasnt prime,choose next prime\n");
    mpz_nextprime(*q, *q);
  }


  printf("p and q generated!!\n");
  printf("p = ");
  mpz_out_str(stdout, 10, *p);
  printf("q = ");
  mpz_out_str(stdout, 10, *q);
  printf("\n------------------------------------------------------------------------------------------\n");
  mpz_clear(seed);
  return;
}

void RSA::computeNandF(mpz_t* q, mpz_t* p, mpz_t *phi, mpz_t* n) {

  mpz_t temp1, temp2;
  mpz_init(temp1);
  mpz_init(temp2);
  //n=p*q
  mpz_mul(*n, *q, *p);
  mpz_sub_ui(temp1, *q, 1); //temp1=q-1
  mpz_sub_ui(temp2, *p, 1); //temp2=p-1
  //φ=(p-1)(q-1)
  mpz_mul(*phi, temp1, temp2);
  printf("phi and n generated!!\n");
  printf(" n= ");
  mpz_out_str(stdout, 10, *n);
  printf("phi = ");
  mpz_out_str(stdout, 10, *phi);
  printf("\n------------------------------------------------------------------------------------------\n");
}

void RSA::generateE(mpz_t* phi, mpz_t* e) {
  mpz_t temp, seed;
  mpz_init(seed);
  mpz_init(temp);
  long sd = 0;
  gmp_randinit(stat, GMP_RAND_ALG_LC, 120);
  srand((unsigned) getpid());
  sd = rand();
  mpz_set_ui(seed, sd);
  gmp_randseed(stat, seed);

  do {
    mpz_urandomm(*e, stat, *phi + 1);
    mpz_gcd(temp, *phi, *e); //temp=gcd(e,φ)
  } while (mpz_cmp_ui(temp, 1) != 0); //όσο το gcd δεν είναι 1
  printf("e generated \n e = ");
  mpz_out_str(stdout, 10, *e);
  printf("\n------------------------------------------------------------------------------------------\n");

}
void RSA::Init(mpz_t& p, mpz_t& q, mpz_t& phi, mpz_t& n, mpz_t& d, mpz_t& e){
  // RSA algorithm
  generatePrimes(&p, &q);
  computeNandF(&q, &p, &phi, &n);
  generateE(&phi, &e);
  // extended Euclidean
  mpz_invert(d, e, phi);
  printf("d = ");
  mpz_out_str(stdout, 10, d);
  printf("\n------------------------------------------------------------------------------------------\n");
}

void RSA::InitCRT(mpz_t& p, mpz_t& q, mpz_t& phi, mpz_t& n, mpz_t& d,  mpz_t& dp, mpz_t& dq, mpz_t& e){
  Init(p, q, phi, n, d, e);
  mpz_t one, pM1, qM1;
  mpz_init_set_ui(one, 1);
  mpz_init(pM1);
  mpz_init(qM1);
  mpz_sub(pM1, p, one); // p - 1
  mpz_mod(dp, d, pM1);
  printf("dp = ");
  mpz_out_str(stdout, 10, dp);
  printf("\n------------------------------------------------------------------------------------------\n");

  mpz_sub(qM1, q, one); // q - 1
  mpz_mod(dq, d, qM1);
  printf("dq = ");
  mpz_out_str(stdout, 10, dq);
  printf("\n------------------------------------------------------------------------------------------\n");
}

void RSA::Encrypt(mpz_t* e, mpz_t* n, mpz_t* d, mpz_t* c, char msg[]) {

  int r[40];
  for (int i = 0; i < strlen(msg); i++)
  {
    r[i] = (int) msg[i];
  }

  int *m = r;
  mpz_t M;
  mpz_init(M);
  mpz_import(M, strlen(msg), 1, sizeof (m[0]), 0, 0, m);
  printf("message as int before encryption  = ");
  mpz_out_str(stdout, 10, M);
  printf("\n");

  mpz_powm(*c, M, *e, *n);

}

void RSA::Decrypt(mpz_t* m, mpz_t* c, mpz_t* d, mpz_t* n) {
  mpz_powm(*m, *c, *d, *n);
}

void RSA::DecryptCRT(mpz_t* m, mpz_t* c, mpz_t* dp, mpz_t* dq, mpz_t* p, mpz_t* q, mpz_t* n) {

  mpz_t mp, mq;
  mpz_init(mp);
  mpz_init(mq);

  mpz_powm(mp, *c, *dp, *p); // mp <- C^{dp} mod p
  mpz_powm(mq, *c, *dq, *q); // mq <- C^{dq} mod q

  mpz_t inv_q;
  mpz_init(inv_q);
  mpz_invert(inv_q, *q, *p);

  /*
  mpz_sub(mp, mp, mq); // mp - mq
  mpz_mul(mp, mp, inv_q); // (mp - mq) * inv_q
  mpz_mod(mp, mp, *p); // ((mp - mq) * inv_q) % p
  mpz_addmul(mq, mp ,*q); // mq + (((mp - mq) * inv_q) % p)*q
  mpz_t zero;
  mpz_init(zero);
  if (mpz_cmp(mq, zero) < 0)
  {
    mpz_add(*m, mq, *n); //m = mq + n;
  }
  else {
    mpz_set(*m, mq); //m = mq;
  }*/
}

/*
void encrFile(mpz_t e, mpz_t n, mpz_t d, mpz_t c) {

  char text[80];
  FILE *file;
  file = fopen("text.txt", "r");
  int i = 0;
  if (file) {
    while ((x = getc(file)) != EOF) {
      i++;
      putchar(x);
      text[i] = (char) x;
    }

    int r[40];
    for (int i = 0; i < strlen(text); i++) {
      r[i] = (int) text[i];
    }

    int *m = r;
    mpz_t M;
    mpz_init(M);
    mpz_import(M, strlen(text), 1, sizeof(m[0]), 0, 0, m);
    printf("message as int before encryption  = ");
    mpz_out_str(stdout, 10, M);
    printf("\n");

    mpz_powm(c, M, e, n);
    printf("encrypt txt  = ");
    mpz_out_str(stdout, 10, c);
    printf("\n");

    fclose(file);
    file = fopen("text.txt", "w");

    mpz_out_raw(file, c);
    fclose(file);

  }
}*/
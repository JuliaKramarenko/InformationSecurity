#include <iostream>
#include <random>
#include <fstream>
#include <chrono>
#include <tuple>
#include "kalyna.h"
#include "aes.h"
#include "rc4.h"
#include "salsa20.h"

#include "sha256.h"
#include "kupyna.h"

#include "rsa.h"
#include "helpers.h"
#include "ecc.h"
#include "../ecc-helpers/gf2.h"
#include "../library/ecc-helpers/curve.h"

#define RUN_CRYPTOSYSTEM 1
#define RUN_CIPHER 0
#define RUN_HASH 1

#define RUN_ECC 1
#define RUN_RSA 1

#define RUN_AES 0
#define RUN_KALYNA 0
#define RUN_RC4 0
#define RUN_SALSA20 0

#define RUN_SHA256 0
#define RUN_KUPYNA 0

const std::string kTestFileName = "test.bin";
const unsigned int BLOCK_BYTES_LENGTH = 16 * sizeof(uint8_t);
size_t const microseconds_in_a_second = 1000 * 1000;
size_t constexpr test_runs = 1u << 3u;

void RunECC(uint8_t input_data[], const int &kBytes)
{
  printf("\nStart ECC");
  auto const &before_ecc = std::chrono::high_resolution_clock::now();
  mpz_class A(1);
  mpz_class B;
  B.set_str("03CE10490F6A708FC26DFE8C3D27C4F94E690134D5BFF988D8D28AAEAEDE975936C66BAC536B18AE2DC312CA493117DAA469C640CAF3", 16);
  mpz_class m(431);
  mpz_class n;
  n.set_str("3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBA3175458009A8C0A724F02F81AA8A1FCBAF80D90C7A95110504CF", 16);
  std::vector<mpz_class> powers = {431, 5, 3, 1, 0};
  EllipticCurve * elcurve = new EllipticCurve(A, B, m, GF::ConvertToFx(powers));
  std::cout << "\nInitializing ECC ";
  ECC ecc = ECC(A, B, m, n, elcurve);
  std::cout<< "\nRunning ECC ";
  std::tuple<unsigned char*, size_t, std::string> signature = ecc.Sign(input_data, kBytes);
  bool verified = ecc.ValidateSignature(signature);
  std::cout<<"verified:" << verified;

  auto const &after_ecc = std::chrono::high_resolution_clock::now();
  printf(
      "ECC on %u bytes took %.6lfs\n",
      kBytes,
      static_cast<double>(std::chrono::duration_cast<std::chrono::microseconds>(after_ecc - before_ecc).count())
          / static_cast<double>(test_runs * microseconds_in_a_second));
  delete elcurve;
}

void Run_RSA (uint8_t input_data[], const int &kBytes)
{
  printf("Start RSA\n");
  mpz_t p, q, phi, e, n, d, dp, dq, c, dc;
  auto const& before_rsa = std::chrono::high_resolution_clock::now();

  const char msg[40] = "welcome to cryptoworld";
  int len = strlen(msg);

  mpz_init(p);
  mpz_init(q);
  mpz_init(phi);
  mpz_init(e);
  mpz_init(n);
  mpz_init(d);
  mpz_init(dp);
  mpz_init(dq);
  mpz_init(c);
  mpz_init(dc);

  RSA rsa = RSA(128, 128);

  //rsa.Init( p, q, phi, n, d, e);
  rsa.InitCRT(p, q, phi, n, d, dp, dq, e);

  //----------OAEP------------------------------------------
  /*// make padding block be block
  int NumOfBlocks = len / 16 + ((len % 16 == 0) ? 0 : 1);
  std::string msgSTR(msg);
  msgSTR.resize(NumOfBlocks * 16, (char) 0);
  // make class
  std::string Xarr[NumOfBlocks];
  std::string Yarr[NumOfBlocks];
  std::string Harr[NumOfBlocks];
  std::string Garr[NumOfBlocks];

  for (int i = 0; i < NumOfBlocks; i++) {
    BlockPaddingOAEP(msgSTR.substr(i * 16, i * 16 + 15), Xarr[i], Yarr[i], Harr[i], Garr[i]);
  }*/
//______________________________________________________________________
  rsa.Encrypt(&e, &n, &d, &c, msg);
  rsa.DecryptCRT(&dc, &c, &dp, &dq, &p, &q, &n);
  //rsa.Decrypt(&dc, &c, &d, &n);
//_________________OAEPP_________________________________________________
  //revert padding block be block
  /*std::string RES = "";
  for (int i = 0; i < NumOfBlocks; i++) {
    std::string temp;
    BlockDepaddingOAEP(temp, Xarr[i], Yarr[i], Harr[i], Garr[i]);
    RES += temp;
  }*/
//________________________________________________________________________________
  //printf("\n------------------------------------------------------------------------------------------\n");
  //printf("encrypt message  = ");
  //mpz_out_str(stdout, 10, c);
  //printf("\n");
  //printf("\n------------------------------------------------------------------------------------------\n");
  printf("message as int after decr  = ");
  mpz_out_str(stdout, 10, dc);
  printf("\n");

  // char *r = mpz_get_str(nullptr, 16, dc);
  //printf("message as string after decr  = ");
  // for (int i = 0; i < strlen(r); i++) {
  // printf("%c", r[i]);
  //}
  printf("\n");
  auto const &after_rsa = std::chrono::high_resolution_clock::now();

  printf(
      "RSA took %.6lfs\n",
      static_cast<double>(std::chrono::duration_cast<std::chrono::microseconds>(after_rsa - before_rsa).count() )
          / static_cast<double>(microseconds_in_a_second));

  mpz_clear(p);
  mpz_clear(dp);
  mpz_clear(q);
  mpz_clear(dq);
  mpz_clear(phi);
  mpz_clear(n);
  mpz_clear(e);
  mpz_clear(c);
  mpz_clear(d);
  mpz_clear(dc);
}

void Cryptosystems(uint8_t input_data[], const int &kBytes){
#if RUN_RSA
  Run_RSA(input_data, kBytes);
#endif // RSA
#if RUN_ECC
  RunECC(input_data,kBytes);
#endif // ECDSA
}

void generate_messages_internal(int length, std::vector<uint8_t> &buffer, std::vector<std::vector<uint8_t>> &result) {
  if (buffer.size() == length) {
    result.push_back(buffer);
  } else {
    for (int value = 0; value < 256; value++) {
      buffer.push_back(value);
      generate_messages_internal(length, buffer, result);
      buffer.pop_back();
    }
  }
}
std::vector<std::vector<uint8_t>> generate_messages(int length) {
  std::vector<std::vector<uint8_t>> result;
  std::vector<uint8_t> buffer;
  generate_messages_internal(length, buffer, result);
  return result;
}
std::string ProofOfWork(SHA256 &sha256, const int length, const uint8_t kZeroBytes) {
  std::string tail_bytes(kZeroBytes, '0');
  const auto messages = generate_messages(length);
  std::string result = "";
  for (const auto &item : messages) {
    auto *message = new uint8_t[item.size()];
    for (size_t i = 0; i < item.size(); i++) {
      message[i] = item[i];
    }

    std::string output = sha256.Hash(message, sizeof(message));
    delete[] message;

    if (output.size() > kZeroBytes && output.substr(output.size() - kZeroBytes) == tail_bytes) {
      result = output;
      break;
    }
  }
  return result;
}
uint8_t *ProofOfWork(Kupyna kupyna, const int length, const uint8_t kZeroBytes) {
  const auto messages = generate_messages(length);
  uint8_t *result = nullptr;

  auto CheckZeros = [](const uint8_t *buffer, const size_t buffer_size) -> bool {
    for (size_t i = 0; i < buffer_size; i++) {
      if (buffer[i]) {
        return false;
      }
    }
    return true;
  };

  for (const auto &item : messages) {
    auto *message = new uint8_t[item.size()];
    for (size_t i = 0; i < item.size(); i++) {
      message[i] = item[i];
    }

    uint8_t hash_code[512 / 8];
    kupyna.Hash(message, 512, hash_code);
    uint8_t *output = hash_code;
    size_t output_size = sizeof(output);
    delete[] message;

    if (output_size > kZeroBytes && CheckZeros((output + output_size - kZeroBytes), kZeroBytes)) {
      result = output;
      break;
    }
  }
  return result;
}

void Hash_functions(uint8_t *input_data, const int &kBytes) {
#if RUN_SHA256
  printf("Start SHA-256\n");
  auto const &before_sha256 = std::chrono::high_resolution_clock::now();

  SHA256 sha256;
  for (size_t test = 0; test < test_runs; test++) {
    std::string output = sha256.Hash(input_data, kBytes);
  }
  auto const &after_sha256 = std::chrono::high_resolution_clock::now();
  printf(
      "SHA-256 on %u bytes took %.6lfs\n",
      kBytes,
      static_cast<double>(std::chrono::duration_cast<std::chrono::microseconds>(after_sha256 - before_sha256).count())
          / static_cast<double>(test_runs * microseconds_in_a_second));
  SHA256 sha256pow;
  auto const &before_sha256_pow = std::chrono::high_resolution_clock::now();
  std::ignore = ProofOfWork(sha256pow, 2, 1);
  auto const &after_sha256_pow = std::chrono::high_resolution_clock::now();
  printf(
      "POW SHA-256 took %.6lfs\n",
      static_cast<double>(std::chrono::duration_cast<std::chrono::microseconds>(
          after_sha256_pow - before_sha256_pow).count())
          / static_cast<double>(test_runs * microseconds_in_a_second));
#endif // SHA-256

#if RUN_KUPYNA
  printf("Start Kupyna\n");
  auto const &before_kupyna = std::chrono::high_resolution_clock::now();

  Kupyna kupyna(256);
  uint8_t hash_code[512 / 8];
  for (size_t test = 0; test < test_runs; test++) {
    kupyna.Hash(input_data, 512, hash_code);
  }
  auto const &after_kupyna = std::chrono::high_resolution_clock::now();
  printf(
      "Kupyna on %u bytes took %.6lfs\n",
      kBytes,
      static_cast<double>(std::chrono::duration_cast<std::chrono::microseconds>(after_kupyna - before_kupyna).count())
          / static_cast<double>(test_runs * microseconds_in_a_second));
  Kupyna kupynaPow(256);
  auto const &before_kupyna_pow = std::chrono::high_resolution_clock::now();
  std::ignore = ProofOfWork(kupynaPow, 2, 1);
  auto const &after_kupyna_pow = std::chrono::high_resolution_clock::now();
  printf(
      "POW Kupyna took %.6lfs\n",
      static_cast<double>(std::chrono::duration_cast<std::chrono::microseconds>(
          after_kupyna_pow - before_kupyna_pow).count())
          / static_cast<double>(test_runs * microseconds_in_a_second));

#endif // Kupyna
}

void Ciphers(uint8_t input_data[], const int &kBytes) {
#if RUN_AES
  const int keyLen = 256;
  AES aes(keyLen);
  unsigned char iv[] =
      {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
  unsigned char key[] =
      {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11,
       0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
  unsigned int len;

  auto const &before_aes = std::chrono::high_resolution_clock::now();

  for (size_t test = 0; test < test_runs; test++) {
    unsigned char *out = aes.EncryptCFB(input_data ,6, kBytes, key, iv,len);
    unsigned char *innew = aes.DecryptCFB(out,6, kBytes, key,iv);
    assert(!memcmp(innew, input_data, kBytes));
    delete[] out;
  }

  auto const &after_aes = std::chrono::high_resolution_clock::now();

  printf(
      "AES(%u) CFB on %u bytes took %.6lfs\n",
      keyLen,
      kBytes,
      static_cast<double>(std::chrono::duration_cast<std::chrono::microseconds>(after_aes - before_aes).count())
          / static_cast< double >(test_runs * microseconds_in_a_second));

#endif //AES

#if RUN_KALYNA
  Kalyna kalyna(256, 256);
  uint64_t key44_e[4] =
      {0x0706050403020100ULL, 0x0f0e0d0c0b0a0908ULL, 0x1716151413121110ULL, 0x1f1e1d1c1b1a1918ULL};
  kalyna.KeyExpand(key44_e);
  uint64_t input[4], ciphered_text[4], output[4];

  auto const &before_kalyna = std::chrono::high_resolution_clock::now();

  for (size_t test = 0; test < test_runs; test++) {
    for (int i = 0; i < kBytes; i += BLOCK_BYTES_LENGTH) {
      memcpy(input, input_data, BLOCK_BYTES_LENGTH);
      kalyna.Encipher(input, ciphered_text);
      kalyna.Decipher(ciphered_text, output);
      assert(memcmp(input, output, sizeof(input)));
    }
  }

  auto const &after_kalyna = std::chrono::high_resolution_clock::now();

  printf(
      "Kalyna(%u, %u) on %u bytes took %.6lfs\n",
      256, 256,
      kBytes,
      static_cast<double>(std::chrono::duration_cast<std::chrono::microseconds>(after_kalyna - before_kalyna).count())
          / static_cast< double >(test_runs * microseconds_in_a_second));

#endif // Kalyna

#if RUN_RC4
  printf("Start RC4\n");
  auto const& before_rc4 = std::chrono::high_resolution_clock::now();

  RC4 rc4{};
  unsigned char key_rc4[] =
     { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11,
        0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };
  uint8_t* enc = new uint8_t[kBytes];
  uint8_t* dec = new uint8_t[kBytes];

  for (size_t test = 0; test < test_runs; test++) {
    //Encipher
    rc4.SetKey(key_rc4, sizeof key_rc4);
    rc4.Encrypt(input_data, enc, kBytes);

    //Decipher
    rc4.SetKey(key_rc4, 32);
    rc4.Encrypt(enc, dec, kBytes);
  }
  auto const& after_rc4 = std::chrono::high_resolution_clock::now();

  printf(
      "RC4 on %u bytes took %.6lfs\n",
      kBytes,
      static_cast<double>(std::chrono::duration_cast<std::chrono::microseconds>(after_rc4 - before_rc4).count())
          / static_cast<double>(test_runs * microseconds_in_a_second));
  delete [] enc;
  delete [] dec;
#endif // RC4

#if RUN_SALSA20
  printf("Start SALSA20\n");
  auto const& before_salsa20 = std::chrono::high_resolution_clock::now();

  Salsa20 salsa20(256);
  uint8_t key_salsa[32] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
                            21,22,23,24,25,26,27,28,29,30,31,32};
  uint8_t n[8] = { 3, 1, 4, 1, 5, 9, 2, 6 };

  for (size_t test = 0; test < test_runs; test++) {
    salsa20.Encrypt(key_salsa, n, 0, input_data, kBytes);
    salsa20.Decrypt(key_salsa, n, 0, input_data, kBytes);}
    auto const &after_salsa20 = std::chrono::high_resolution_clock::now();
  printf(
      "Salsa20 on %u bytes took %.6lfs\n",
      kBytes,
      static_cast<double>(std::chrono::duration_cast<std::chrono::microseconds>(after_salsa20 - before_salsa20).count())
          / static_cast<double>(test_runs * microseconds_in_a_second));

#endif // SALSA20
}

inline bool FileExists(const std::string &name) {
  std::ifstream f(name.c_str());
  return f.good();
}

void GenerateData(const int &kBytes) {
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<> distrib(std::numeric_limits<uint8_t>::min(), std::numeric_limits<uint8_t>::max());

  std::cout << "Starting data generation" << std::endl;

  if (!FileExists(kTestFileName)) {
    std::ofstream test_file;
    test_file.open(kTestFileName, std::ios::out | std::ios::binary);

    if (test_file.is_open()) {
      for (int i = 0; i < kBytes; i++) {
        test_file << (unsigned char) distrib(gen);
      }
      test_file.close();
    }
  }

  std::cout << "Data generation finished" << std::endl;
}

void Measurement(const int &kBytes = 1'000'000) {

  auto *input_data = new uint8_t[kBytes];
  if (FileExists(kTestFileName)) {
    std::ifstream input(kTestFileName.c_str(), std::ios::in | std::ios::binary);
    if (input.is_open()) {
      for (int i = 0; i < kBytes; i++) {
        input >> input_data[i];
      }
    }
  } else {
    std::cout << "Couldn't find testing file" << std::endl;
    exit(1);
  }

#if RUN_CIPHER
  Ciphers(input_data, kBytes);
#endif // CIPHER

#if RUN_HASH
  Hash_functions(input_data, kBytes);
#endif // HASH

#if RUN_CRYPTOSYSTEM
 Cryptosystems(input_data,kBytes);
#endif // DIGITAL SIGNING
  delete[] input_data;
}

int main() {
  int kBytesInGigabyte = 1'000'000'000;
  int kBytesInMegabyte = 1'000'000;
  GenerateData(kBytesInMegabyte);
  Measurement(kBytesInMegabyte);
  exit(0);
  //return 0;
}
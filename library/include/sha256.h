#ifndef AES_KALYNA_SHA256_H
#define AES_KALYNA_SHA256_H

#include <cstdint>
#include <string>

  class SHA256
  {
   public:
    const uint32_t h0 = 0x6a09e667;
    const uint32_t h1 = 0xbb67ae85;
    const uint32_t h2 = 0x3c6ef372;
    const uint32_t h3 = 0xa54ff53a;
    const uint32_t h4 = 0x510e527f;
    const uint32_t h5 = 0x9b05688c;
    const uint32_t h6 = 0x1f83d9ab;
    const uint32_t h7 = 0x5be0cd19;

    static const uint32_t DIGEST_SIZE = (256 / 8);
    std::string Hash(std::string in);
    std::string Hash(uint8_t* in, uint32_t inLen);

   private:
    const static uint32_t sha256_k[];
    static const uint32_t SHA224_256_BLOCK_SIZE = (512 / 8);
    uint32_t m_tot_len;
    uint32_t m_len;
    uint8_t m_block[2 * SHA224_256_BLOCK_SIZE];
    uint32_t m_h[8];

    uint32_t ShR(uint32_t value, int shift);
    uint32_t RotR(uint32_t value, int shift);
    uint32_t CH(uint32_t x, uint32_t y, uint32_t z);//choose
    uint32_t MAJ(uint32_t x, uint32_t y, uint32_t z);//majority
    uint32_t F1(uint32_t x);
    uint32_t F2(uint32_t x);
    uint32_t F3(uint32_t x);
    uint32_t F4(uint32_t x);
    void Transform(const uint8_t* message, uint32_t block_nb);

    void Init();
    void Update(const uint8_t* message, uint32_t inLen);
    void Final(uint8_t* digest);
  };

  #define SHA2_UNPACK32(x, str)                   \
  {                                               \
      *((str) + 3) = (uint8_t) ((x)      );       \
      *((str) + 2) = (uint8_t) ((x) >>  8);       \
      *((str) + 1) = (uint8_t) ((x) >> 16);       \
      *((str) + 0) = (uint8_t) ((x) >> 24);       \
  }
  #define SHA2_PACK32(str, x)                     \
  {                                               \
      *(x) =   ((uint32_t) *((str) + 3)      )    \
             | ((uint32_t) *((str) + 2) <<  8)    \
             | ((uint32_t) *((str) + 1) << 16)    \
             | ((uint32_t) *((str) + 0) << 24);   \
  }
#endif //AES_KALYNA_SHA256_H

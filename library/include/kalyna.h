#ifndef AES_KALYNA_LIBRARY_INCLUDE_KALYNA_H_
#define AES_KALYNA_LIBRARY_INCLUDE_KALYNA_H_

#include <cstdint>
#include <cstdlib>
#include <cstring>

class Kalyna {
 public:
  Kalyna(size_t block_size, size_t key_size);

  /*!
 * Compute round keys given the enciphering key and store them in cipher.
 *
 * @param key Kalyna enciphering key.
 */
  void KeyExpand(uint64_t *key);

  /*!
 * Encipher plaintext using Kalyna symmetric block cipher.
 *
 * @param plaintext Plaintext of length Nb words for enciphering.
 * @param ciphertext The result of enciphering.
 */
  void Encipher(uint64_t *plaintext, uint64_t *ciphertext);

  /*!
 * Decipher ciphertext using Kalyna symmetric block cipher.
 *
 * @param ciphertext Enciphered data of length Nb words.
 * @param plaintext The result of deciphering.
 */
  void Decipher(uint64_t *ciphertext, uint64_t *plaintext);

  ~Kalyna();

 private:
  void KeyExpandKt(uint64_t *key, uint64_t *kt);

  void KeyExpandEven(uint64_t *key, uint64_t *kt);

  void KeyExpandOdd();

 private:
  // Number of 64-bit words in enciphering block.
  size_t nb;
  // Number of 64-bit words in key.
  size_t nk;
  // Number of enciphering rounds.
  size_t nr;
  // Current cipher state.
  uint64_t *state;
  // Round key computed from enciphering key.
  uint64_t **round_keys;
};

#endif //AES_KALYNA_LIBRARY_INCLUDE_KALYNA_H_

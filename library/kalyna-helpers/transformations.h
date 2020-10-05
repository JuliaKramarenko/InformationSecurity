#ifndef AES_KALYNA_LIBRARY_KALYNA_HELPERS_TRANSFORMATIONS_H_
#define AES_KALYNA_LIBRARY_KALYNA_HELPERS_TRANSFORMATIONS_H_

#include <cstdint>
#include <climits>

static_assert(ULLONG_MAX == 0xFFFFFFFFFFFFFFFFULL, "Architecture not supported. Required type to fit 64 bits.");
static_assert(CHAR_BIT == 8, "Architecture not supported. Required type to fit 8 bits.");

const size_t kBITS_IN_WORD = 64;

const size_t kBITS_IN_BYTE = 8;

/* Block words size. */
const size_t kNB_128 = 2;
const size_t kNB_256 = 4;
const size_t kNB_512 = 8;

/* Key words size. */
const size_t kNK_128 = 2;
const size_t kNK_256 = 4;
const size_t kNK_512 = 8;

/* Block bits size. */
const size_t kBLOCK_128 = kNB_128 * kBITS_IN_WORD;
const size_t kBLOCK_256 = kNB_256 * kBITS_IN_WORD;
const size_t kBLOCK_512 = kNB_512 * kBITS_IN_WORD;

/* Block bits size. */
const size_t kKEY_128 = kNK_128 * kBITS_IN_WORD;
const size_t kKEY_256 = kNK_256 * kBITS_IN_WORD;
const size_t kKEY_512 = kNK_512 * kBITS_IN_WORD;

/* Number of enciphering rounds size depending on key length. */
const size_t kNR_128 = 10;
const size_t kNR_256 = 14;
const size_t kNR_512 = 18;

/* x^8 + x^4 + x^3 + x^2 + 1 */
const size_t kREDUCTION_POLYNOMIAL = 0x011du;

/*!
 * Substitute each byte of the cipher state using corresponding S-Boxes.
 */
void SubBytes(uint64_t *state, size_t nb);

/*!
 * Inverse SubBytes transformation.
 */
void InvSubBytes(uint64_t *state, size_t nb);

/*!
 * Shift cipher state rows according to specification.
 */
void ShiftRows(uint64_t *&state, size_t nb);

/*!
 * Inverse ShiftRows transformation.
 */
void InvShiftRows(uint64_t *&state, size_t nb);

/*!
 * Multiply bytes in Finite Field GF(2^8).
 *
 * @param x Multiplicand element of GF(2^8).
 * @param y Multiplier element of GF(2^8) from MDS matrix.
 * @return Product of multiplication in GF(2^8).
 */
uint8_t MultiplyGF(uint8_t x, uint8_t y);

/*!
 * Multiply cipher state by specified MDS matrix.
 * Used to avoid code repetition for MixColumn and Inverse MixColumn.
 *
 * @param matrix MDS 8x8 byte matrix.
 */
void MatrixMultiply(uint64_t *state, size_t nb, uint8_t matrix[8][8]);

/*!
 * Perform MixColumn transformation to the cipher state.
 */
void MixColumns(uint64_t *state, size_t nb);

/*!
 * Inverse MixColumn transformation.
 */
void InvMixColumns(uint64_t *state, size_t nb);

/*!
 * Perform single round enciphering routine.
 */
void EncipherRound(uint64_t *&state, size_t nb);

/*!
 * Perform single round deciphering routine.
 */
void DecipherRound(uint64_t *&state, size_t nb);

/*!
 * Inject round key into the state using addition modulo 2^{64}.
 *
 * @param round Number of the round on which the key addition is performed in
 * order to use the correct round key.
 */
void AddRoundKey(int round, uint64_t *state, uint64_t **round_keys, size_t nb);

/*!
 * Extract round key from the state using subtraction modulo 2^{64}.
 *
 * @param round Number of the round on which the key subtraction is performed
 * in order to use the correct round key.
 */
void SubRoundKey(int round, uint64_t *state, uint64_t **round_keys, size_t nb);

/*!
 * Perform addition of two arbitrary states modulo 2^{64}.
 * The operation is identical to simple round key addition but on arbitrary
 * state array and addition value (instead of the actual round key). Used in
 * key expansion procedure. The result is stored in `state`.
 *
 * @param value Is to be added to the state array modulo 2^{64}.
 */
void AddRoundKeyExpand(const uint64_t *value, uint64_t *state, size_t nb);

/*!
 * Inject round key into the state using XOR operation.
 *
 * @param round Number of the round on which the key addition is performed in
 * order to use the correct round key.
 */
void XorRoundKey(int round, uint64_t *state, uint64_t **round_keys, size_t nb);

/*!
 * Perform XOR of two arbitrary states.
 * The operation is identical to simple round key XORing but on arbitrary
 * state array and addition value (instead of the actual round key). Used in
 * key expansion procedure. The result is stored in `state`.
 * XOR operation is involutive so no inverse transformation is required.
 *
 * @param value Is to be added to the state array modulo 2^{64}.
 */
void XorRoundKeyExpand(const uint64_t *value, uint64_t *state, size_t nb);

/*!
 * Rotate words of a state.
 * The state is processed as 64-bit words array {w_{0}, w_{1}, ..., w_{nk-1}}
 * and rotation is performed so the resulting state is
 * {w_{1}, ..., w_{nk-1}, w_{0}}.
 *
 * @param state_value A state represented by 64-bit words array of length Nk.
 * It is not the cipher state that is used during enciphering.
 */
void Rotate(size_t state_size, uint64_t *state_value);

/*!
 * Shift each word one bit to the left.
 * The shift of each word is independent of other array words.
 *
 * @param state_size Size of the state to be shifted.
 * @param state_value State represented as 64-bit words array.  Note that this
 * state Nk words long and differs from the cipher state used during
 * enciphering.
 */
void ShiftLeft(size_t state_size, uint64_t *state_value);

/*!
 * Rotate the state (2 * Nb + 3) bytes to the left.
 * The state is interpreted as bytes string in little endian. Big endian
 * architectures are also correctly processed by this function.
 *
 * @param ctx Initialized cipher context with current state and round keys
 * precomputed.
 * @param state_value A state represented by 64-bit words array of length Nk.
 * It is not the cipher state that is used during enciphering.
 */
void RotateLeft(size_t state_size, uint64_t *&state_value);

/*!
 * Convert array of 64-bit words to array of bytes.
 * Each word is interpreted as byte sequence following little endian
 * convention. However a check for big endian and corresponding word reversion
 * is performed if needed.
 *
 * @param length Length of 64-bit words array.
 * @param words Pointer to 64-bit words array.
 * @return Pointer to bytes array.
 */
uint8_t *WordsToBytes(size_t length, uint64_t *words);

/*!
 * Convert array of bytes to array of 64-bit words.
 * Each word is interpreted as byte sequence following little endian
 * convention. However a check for big endian and corresponding word reversion
 * is performed if needed.
 *
 * @param length Length of bytes array.
 * @param words Pointer to bytes array.
 * @return Pointer to 64-bit words array.
 */
uint64_t *BytesToWords(size_t length, uint8_t *bytes);

/*!
 * Reverse bytes ordering that form the word.
 *
 * @param word 64-bit word that needs its bytes to be reversed (perhaps for
 * converting between little and big endian).
 * @return 64-bit word with reversed bytes.
 */
uint64_t ReverseWord(uint64_t word);

/*!
 * Check if architecture follows big endian convention.
 *
 * @return 1 if architecture is big endian, 0 if it is little endian.
 */
int IsBigEndian();

#endif //AES_KALYNA_LIBRARY_KALYNA_HELPERS_TRANSFORMATIONS_H_

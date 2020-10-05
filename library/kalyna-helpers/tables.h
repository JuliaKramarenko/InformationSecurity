#ifndef AES_KALYNA_LIBRARY_KALYNA_HELPERS_TABLES_H_
#define AES_KALYNA_LIBRARY_KALYNA_HELPERS_TABLES_H_

#include <cstdint>

extern const uint8_t mds_matrix[8][8];
extern const uint8_t mds_inv_matrix[8][8];

extern const uint8_t sboxes_enc[4][256];
extern const uint8_t sboxes_dec[4][256];

#endif //AES_KALYNA_LIBRARY_KALYNA_HELPERS_TABLES_H_

#include <stdexcept>
#include "kalyna.h"
#include "transformations.h"
#include "tables.h"

Kalyna::Kalyna(size_t block_size, size_t key_size) {
  if (block_size == kBLOCK_128) {
    nb = kBLOCK_128 / kBITS_IN_WORD;
    if (key_size == kKEY_128) {
      nk = kKEY_128 / kBITS_IN_WORD;
      nr = kNR_128;
    } else if (key_size == kKEY_256) {
      nk = kKEY_256 / kBITS_IN_WORD;
      nr = kNR_256;
    } else {
      throw std::invalid_argument("Error: unsupported key size");
    }
  } else if (block_size == 256) {
    nb = kBLOCK_256 / kBITS_IN_WORD;
    if (key_size == kKEY_256) {
      nk = kKEY_256 / kBITS_IN_WORD;
      nr = kNR_256;
    } else if (key_size == kKEY_512) {
      nk = kKEY_512 / kBITS_IN_WORD;
      nr = kNR_512;
    } else {
      throw std::invalid_argument("Error: unsupported key size");
    }
  } else if (block_size == kBLOCK_512) {
    nb = kBLOCK_512 / kBITS_IN_WORD;
    if (key_size == kKEY_512) {
      nk = kKEY_512 / kBITS_IN_WORD;
      nr = kNR_512;
    } else {
      throw std::invalid_argument("Error: unsupported key size");
    }
  } else {
    throw std::invalid_argument("Error: unsupported key size");
  }

  state = (uint64_t *) calloc(nb, sizeof(uint64_t));
  if (!state) {
    throw std::runtime_error("Could not allocate memory for cipher state.");
  }

  round_keys = (uint64_t **) calloc(nr + 1, sizeof(uint64_t **));
  if (!round_keys) {
    throw std::runtime_error("Could not allocate memory for cipher round keys.");
  }

  for (size_t i = 0; i < nr + 1; ++i) {
    round_keys[i] = (uint64_t *) calloc(nb, sizeof(uint64_t));
    if (!round_keys[i]) {
      throw std::runtime_error("Could not allocate memory for cipher round keys.");
    }
  }
}

Kalyna::~Kalyna() {
  free(state);
  for (size_t i = 0; i < nr + 1; ++i) {
    free(round_keys[i]);
  }
  free(round_keys);
}

void Kalyna::KeyExpand(uint64_t *key) {
  auto *kt = (uint64_t *) malloc(nb * sizeof(uint64_t));
  KeyExpandKt(key, kt);
  KeyExpandEven(key, kt);
  KeyExpandOdd();
  free(kt);
}

void Kalyna::KeyExpandKt(uint64_t *key, uint64_t *kt) {
  auto *k0 = (uint64_t *) malloc(nb * sizeof(uint64_t));
  auto *k1 = (uint64_t *) malloc(nb * sizeof(uint64_t));

  memset(state, 0, nb * sizeof(uint64_t));
  state[0] += nb + nk + 1;

  if (nb == nk) {
    memcpy(k0, key, nb * sizeof(uint64_t));
    memcpy(k1, key, nb * sizeof(uint64_t));
  } else {
    memcpy(k0, key, nb * sizeof(uint64_t));
    memcpy(k1, key + nb, nb * sizeof(uint64_t));
  }

  AddRoundKeyExpand(k0, state, nb);
  EncipherRound(state, nb);
  XorRoundKeyExpand(k1, state, nb);
  EncipherRound(state, nb);
  AddRoundKeyExpand(k0, state, nb);
  EncipherRound(state, nb);
  memcpy(kt, state, nb * sizeof(uint64_t));

  free(k0);
  free(k1);
}

void Kalyna::KeyExpandEven(uint64_t *key, uint64_t *kt) {
  auto *initial_data = (uint64_t *) malloc(nk * sizeof(uint64_t));
  auto *kt_round = (uint64_t *) malloc(nb * sizeof(uint64_t));
  auto *tmv = (uint64_t *) malloc(nb * sizeof(uint64_t));
  size_t round = 0;

  memcpy(initial_data, key, nk * sizeof(uint64_t));
  for (size_t i = 0; i < nb; ++i) {
    tmv[i] = 0x0001000100010001;
  }

  while (true) {
    memcpy(state, kt, nb * sizeof(uint64_t));
    AddRoundKeyExpand(tmv, state, nb);
    memcpy(kt_round, state, nb * sizeof(uint64_t));

    memcpy(state, initial_data, nb * sizeof(uint64_t));

    AddRoundKeyExpand(kt_round, state, nb);
    EncipherRound(state, nb);
    XorRoundKeyExpand(kt_round, state, nb);
    EncipherRound(state, nb);
    AddRoundKeyExpand(kt_round, state, nb);

    memcpy(round_keys[round], state, nb * sizeof(uint64_t));

    if (nr == round)
      break;

    if (nk != nb) {
      round += 2;

      ShiftLeft(nb, tmv);

      memcpy(state, kt, nb * sizeof(uint64_t));
      AddRoundKeyExpand(tmv, state, nb);
      memcpy(kt_round, state, nb * sizeof(uint64_t));

      memcpy(state, initial_data + nb, nb * sizeof(uint64_t));

      AddRoundKeyExpand(kt_round, state, nb);
      EncipherRound(state, nb);
      XorRoundKeyExpand(kt_round, state, nb);
      EncipherRound(state, nb);
      AddRoundKeyExpand(kt_round, state, nb);

      memcpy(round_keys[round], state, nb * sizeof(uint64_t));

      if (nr == round)
        break;
    }
    round += 2;
    ShiftLeft(nb, tmv);
    Rotate(nk, initial_data);
  }

  free(initial_data);
  free(kt_round);
  free(tmv);
}

void Kalyna::KeyExpandOdd() {
  for (size_t i = 1; i < nr; i += 2) {
    memcpy(round_keys[i], round_keys[i - 1], nb * sizeof(uint64_t));
    RotateLeft(nb, round_keys[i]);
  }
}

void Kalyna::Encipher(uint64_t *plaintext, uint64_t *ciphertext) {
  memcpy(state, plaintext, nb * sizeof(uint64_t));

  AddRoundKey(0, state, round_keys, nb);
  for (size_t round = 1; round < nr; ++round) {
    EncipherRound(state, nb);
    XorRoundKey(round, state, round_keys, nb);
  }
  EncipherRound(state, nb);
  AddRoundKey(nr, state, round_keys, nb);

  memcpy(ciphertext, state, nb * sizeof(uint64_t));
}

void Kalyna::Decipher(uint64_t *ciphertext, uint64_t *plaintext) {
  memcpy(state, ciphertext, nb * sizeof(uint64_t));

  SubRoundKey(nr, state, round_keys, nb);
  for (size_t round = nr - 1; round > 0; --round) {
    DecipherRound(state, nb);
    XorRoundKey(round, state, round_keys, nb);
  }
  DecipherRound(state, nb);
  SubRoundKey(0, state, round_keys, nb);

  memcpy(plaintext, state, nb * sizeof(uint64_t));
}

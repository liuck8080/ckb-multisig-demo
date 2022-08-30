#include "blake2b.h"
#include "blockchain.h"
#include "secp256k1_helper.h"
#include "secp256k1_lock.h"

/* 32 KB */
#define ONE_BATCH_SIZE 32768

/*
 * data should at least be CKB_SECP256K1_DATA_SIZE big
 * so as to hold all loaded data.
 */
int ckb_secp256k1_custom_load_data(void *data) {
  size_t index = SIZE_MAX;
  int ret = ckb_look_for_dep_with_hash(ckb_secp256k1_data_hash, &index);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  /* Found a match, load data here */
  uint64_t len = CKB_SECP256K1_DATA_SIZE;
  ret = ckb_load_cell_data(data, &len, 0, index, CKB_SOURCE_CELL_DEP);
  if (ret != CKB_SUCCESS || len != CKB_SECP256K1_DATA_SIZE) {
    return CKB_SECP256K1_HELPER_ERROR_LOADING_DATA;
  }
  return CKB_SUCCESS;
}

int load_and_hash_witness(blake2b_state *ctx, size_t index, size_t source) {
  uint8_t temp[ONE_BATCH_SIZE];
  uint64_t len = ONE_BATCH_SIZE;
  int ret = ckb_load_witness(temp, &len, 0, index, source);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  blake2b_update(ctx, (char *)&len, sizeof(uint64_t));
  uint64_t offset = (len > ONE_BATCH_SIZE) ? ONE_BATCH_SIZE : len;
  blake2b_update(ctx, temp, offset);
  while (offset < len) {
    uint64_t current_len = ONE_BATCH_SIZE;
    ret = ckb_load_witness(temp, &current_len, offset, index, source);
    if (ret != CKB_SUCCESS) {
      return ret;
    }
    uint64_t current_read =
        (current_len > ONE_BATCH_SIZE) ? ONE_BATCH_SIZE : current_len;
    blake2b_update(ctx, temp, current_read);
    offset += current_read;
  }
  return CKB_SUCCESS;
}

int validate_secp256k1_blake2b_sighash_all(uint8_t *output_public_key_hash) {
  unsigned char temp[TEMP_SIZE];
  unsigned char lock_bytes[SIGNATURE_SIZE];
  uint64_t len = 0;

  // Load witness of first input
  uint64_t witness_len = MAX_WITNESS_SIZE;
  int ret = ckb_load_witness(temp, &witness_len, 0, 0, CKB_SOURCE_GROUP_INPUT);
  if (ret != CKB_SUCCESS) {
    return ERROR_SYSCALL;
  }

  if (witness_len > MAX_WITNESS_SIZE) {
    return ERROR_WITNESS_SIZE;
  }

  // load signature
  mol_seg_t lock_bytes_seg;
  ret = extract_witness_lock(temp, witness_len, &lock_bytes_seg);
  if (ret != 0) {
    return ERROR_ENCODING;
  }

  if (lock_bytes_seg.size != SIGNATURE_SIZE) {
    return ERROR_ARGUMENTS_LEN;
  }
  memcpy(lock_bytes, lock_bytes_seg.ptr, lock_bytes_seg.size);

  // Load tx hash
  unsigned char tx_hash[BLAKE2B_BLOCK_SIZE];
  len = BLAKE2B_BLOCK_SIZE;
  ret = ckb_load_tx_hash(tx_hash, &len, 0);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  if (len != BLAKE2B_BLOCK_SIZE) {
    return ERROR_SYSCALL;
  }

  // Prepare sign message
  unsigned char message[BLAKE2B_BLOCK_SIZE];
  blake2b_state blake2b_ctx;
  blake2b_init(&blake2b_ctx, BLAKE2B_BLOCK_SIZE);
  blake2b_update(&blake2b_ctx, tx_hash, BLAKE2B_BLOCK_SIZE);

  // Clear lock field to zero, then digest the first witness
  memset((void *)lock_bytes_seg.ptr, 0, lock_bytes_seg.size);
  blake2b_update(&blake2b_ctx, (char *)&witness_len, sizeof(uint64_t));
  blake2b_update(&blake2b_ctx, temp, witness_len);

  // Digest same group witnesses
  size_t i = 1;
  while (1) {
    ret = load_and_hash_witness(&blake2b_ctx, i, CKB_SOURCE_GROUP_INPUT);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != CKB_SUCCESS) {
      return ERROR_SYSCALL;
    }
    i += 1;
  }
  // Digest witnesses that not covered by inputs
  i = ckb_calculate_inputs_len();
  while (1) {
    ret = load_and_hash_witness(&blake2b_ctx, i, CKB_SOURCE_INPUT);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != CKB_SUCCESS) {
      return ERROR_SYSCALL;
    }
    i += 1;
  }
  blake2b_final(&blake2b_ctx, message, BLAKE2B_BLOCK_SIZE);

  // Load signature
  secp256k1_context context;
  uint8_t secp_data[CKB_SECP256K1_DATA_SIZE];
  ret = ckb_secp256k1_custom_load_data(secp_data);
  if (ret != 0) {
    return ret;
  }
  ret = ckb_secp256k1_custom_verify_only_initialize(&context, secp_data);
  if (ret != 0) {
    return ret;
  }

  secp256k1_ecdsa_recoverable_signature signature;
  if (secp256k1_ecdsa_recoverable_signature_parse_compact(
          &context, &signature, lock_bytes, lock_bytes[RECID_INDEX]) == 0) {
    return ERROR_SECP_PARSE_SIGNATURE;
  }

  // Recover pubkey
  secp256k1_pubkey pubkey;
  if (secp256k1_ecdsa_recover(&context, &pubkey, &signature, message) != 1) {
    return ERROR_SECP_RECOVER_PUBKEY;
  }

  // Check pubkey hash
  size_t pubkey_size = PUBKEY_SIZE;
  if (secp256k1_ec_pubkey_serialize(&context, temp, &pubkey_size, &pubkey,
                                    SECP256K1_EC_COMPRESSED) != 1) {
    return ERROR_SECP_SERIALIZE_PUBKEY;
  }

  blake2b_init(&blake2b_ctx, BLAKE2B_BLOCK_SIZE);
  blake2b_update(&blake2b_ctx, temp, pubkey_size);
  blake2b_final(&blake2b_ctx, temp, BLAKE2B_BLOCK_SIZE);

  memcpy(output_public_key_hash, temp, BLAKE160_SIZE);

  return CKB_SUCCESS;
}



#define FLAGS_SIZE 4
#define TEMP_SIZE 32768
#define ERROR_VERIFICATION -52

int32_t ckb_secp256k1_verify(uint8_t require_first_n, uint8_t threshold, uint8_t pubkeys_cnt,
                         unsigned char * message, unsigned char * lock_bytes, size_t multisig_script_len) {

  unsigned char temp[TEMP_SIZE];
  // Verify threshold signatures, threshold is a uint8_t, at most it is
  // 255, meaning this array will definitely have a reasonable upper bound.
  // Also this code uses C99's new feature to allocate a variable length array.
  uint8_t used_signatures[pubkeys_cnt];
  memset(used_signatures, 0, pubkeys_cnt);

  // We are using bitcoin's [secp256k1 library](https://github.com/bitcoin-core/secp256k1)
  // for signature verification here. To the best of our knowledge, this is an unmatched
  // advantage of CKB: you can ship cryptographic algorithm within your smart contract,
  // you don't have to wait for the foundation to ship a new cryptographic algorithm. You
  // can just build and ship your own.
  secp256k1_context context;
  uint8_t secp_data[CKB_SECP256K1_DATA_SIZE];
  int32_t ret = ckb_secp256k1_custom_verify_only_initialize(&context, secp_data);
  if (ret != 0) {
    return ret;
  }

  // We will perform *threshold* number of signature verifications here.
  for (size_t i = 0; i < threshold; i++) {
    // Load signature
    secp256k1_ecdsa_recoverable_signature signature;
    size_t signature_offset = multisig_script_len + i * SIGNATURE_SIZE;
    if (secp256k1_ecdsa_recoverable_signature_parse_compact(
            &context, &signature, &lock_bytes[signature_offset],
            lock_bytes[signature_offset + RECID_INDEX]) == 0) {
      return ERROR_SECP_PARSE_SIGNATURE;
    }

    // verifiy signature and Recover pubkey
    secp256k1_pubkey pubkey;
    if (secp256k1_ecdsa_recover(&context, &pubkey, &signature, message) != 1) {
      return ERROR_SECP_RECOVER_PUBKEY;
    }

    // Calculate the blake160 hash of the derived public key
    size_t pubkey_size = PUBKEY_SIZE;
    if (secp256k1_ec_pubkey_serialize(&context, temp, &pubkey_size, &pubkey,
                                      SECP256K1_EC_COMPRESSED) != 1) {
      return ERROR_SECP_SERIALIZE_PUBKEY;
    }

    unsigned char calculated_pubkey_hash[BLAKE2B_BLOCK_SIZE];
    blake2b_state blake2b_ctx;
    blake2b_init(&blake2b_ctx, BLAKE2B_BLOCK_SIZE);
    blake2b_update(&blake2b_ctx, temp, PUBKEY_SIZE);
    blake2b_final(&blake2b_ctx, calculated_pubkey_hash, BLAKE2B_BLOCK_SIZE);

    // Check if this signature is signed with one of the provided public key.
    uint8_t matched = 0;
    for (size_t i = 0; i < pubkeys_cnt; i++) {
      if (used_signatures[i] == 1) {
        continue;
      }
      if (memcmp(&lock_bytes[FLAGS_SIZE + i * BLAKE160_SIZE],
                 calculated_pubkey_hash, BLAKE160_SIZE) != 0) {
        continue;
      }
      matched = 1;
      used_signatures[i] = 1;
      break;
    }

    // If the signature doesn't match any of the provided public key, the script
    // will exit with an error.
    if (matched != 1) {
      return ERROR_VERIFICATION;
    }
  }

  // The above scheme just ensures that a *threshold* number of signatures have
  // successfully been verified, and they all come from the provided public keys.
  // However, the multisig script might also require some numbers of public keys
  // to always be signed for the script to pass verification. This is indicated
  // via the *required_first_n* flag. Here we also checks to see that this rule
  // is also satisfied.
  for (size_t i = 0; i < require_first_n; i++) {
    if (used_signatures[i] != 1) {
      return ERROR_VERIFICATION;
    }
  }
  return 0;
}
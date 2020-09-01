#include "blake2b.h"
#include "ckb_syscalls.h"
#include "keccak256.h"
#include "protocol.h"
#include "secp256k1_helper.h"

#define BLAKE160_SIZE 20
#define SCRIPT_SIZE 32768
#define LOCK_ARGS_SIZE 20
#define DATE_SIZE 256
#define PUBKEY_SIZE 65
#define TEMP_SIZE 32768
#define RECID_INDEX 64

/* 32 KB */
#define MAX_WITNESS_SIZE 32768
#define SCRIPT_SIZE 32768
#define SIGNATURE_SIZE 65

// error code
#define ERROR_ARGUMENTS_LEN -1
#define ERROR_ENCODING -2
#define ERROR_SYSCALL -3
#define ERROR_SCRIPT_TOO_LONG -21
#define ERROR_OUTPUT -81
/* secp256k1 unlock errors */
#define ERROR_SECP_RECOVER_PUBKEY -11
#define ERROR_SECP_VERIFICATION -12
#define ERROR_SECP_PARSE_PUBKEY -13
#define ERROR_SECP_PARSE_SIGNATURE -14
#define ERROR_SECP_SERIALIZE_PUBKEY -15
#define ERROR_SCRIPT_TOO_LONG -21
#define ERROR_WITNESS_SIZE -22
#define ERROR_INCORRECT_SINCE_FLAGS -23
#define ERROR_INCORRECT_SINCE_VALUE -24
#define ERROR_PUBKEY_BLAKE160_HASH -31

int read_args(unsigned char *eth_address) {
  int ret;
  uint64_t len = 0;

  /* Load args */
  unsigned char script[SCRIPT_SIZE];
  len = SCRIPT_SIZE;
  ret = ckb_load_script(script, &len, 0);
  if (ret != CKB_SUCCESS) {
    return ERROR_SYSCALL;
  }
  if (len > SCRIPT_SIZE) {
    return ERROR_SCRIPT_TOO_LONG;
  }
  mol_seg_t script_seg;
  script_seg.ptr = (uint8_t *)script;
  script_seg.size = len;

  if (MolReader_Script_verify(&script_seg, false) != MOL_OK) {
    return ERROR_ENCODING;
  }

  mol_seg_t args_seg = MolReader_Script_get_args(&script_seg);
  mol_seg_t args_bytes_seg = MolReader_Bytes_raw_bytes(&args_seg);
  if (args_bytes_seg.size != LOCK_ARGS_SIZE) {
    return ERROR_ARGUMENTS_LEN;
  }
  memcpy(eth_address, args_bytes_seg.ptr, BLAKE160_SIZE);

  return CKB_SUCCESS;
}

int verify_signature(unsigned char *message, unsigned char *signed_bytes,
                     const void *args) {
  unsigned char temp[TEMP_SIZE];

  /* Load signature */
  secp256k1_context context;
  uint8_t secp_data[CKB_SECP256K1_DATA_SIZE];
  int ret = ckb_secp256k1_custom_verify_only_initialize(&context, secp_data);
  if (ret != 0) {
    return ret;
  }

  secp256k1_ecdsa_recoverable_signature signature;
  if (secp256k1_ecdsa_recoverable_signature_parse_compact(
          &context, &signature, signed_bytes, signed_bytes[RECID_INDEX]) == 0) {
    return ERROR_SECP_PARSE_SIGNATURE;
  }

  /* Recover pubkey */
  secp256k1_pubkey pubkey;
  if (secp256k1_ecdsa_recover(&context, &pubkey, &signature, message) != 1) {
    return ERROR_SECP_RECOVER_PUBKEY;
  }

  /* Check pubkey hash */
  size_t pubkey_size = PUBKEY_SIZE;
  if (secp256k1_ec_pubkey_serialize(&context, temp, &pubkey_size, &pubkey,
                                    SECP256K1_EC_UNCOMPRESSED) != 1) {
    return ERROR_SECP_SERIALIZE_PUBKEY;
  }

  SHA3_CTX sha3_ctx;
  keccak_init(&sha3_ctx);
  keccak_update(&sha3_ctx, &temp[1], pubkey_size - 1);
  keccak_final(&sha3_ctx, temp);

  printf("args: %p\n", args);
  printf("temp: %p\n", temp);

  if (memcmp(args, &temp[12], BLAKE160_SIZE) != 0) {
    return ERROR_PUBKEY_BLAKE160_HASH;
  }

  return CKB_SUCCESS;
}

int verify_secp256k1_keccak_sighash_all(
    unsigned char message[DATE_SIZE],
    unsigned char eth_address[BLAKE160_SIZE]) {
  unsigned char signature[SIGNATURE_SIZE];
  unsigned char origin[32];

  uint64_t witness_len = SIGNATURE_SIZE;
  size_t ret =
      ckb_load_witness(signature, &witness_len, 0, 1, CKB_SOURCE_GROUP_INPUT);
  if (ret != CKB_SUCCESS) {
    return ERROR_SYSCALL;
  }
  if (witness_len != SIGNATURE_SIZE) {
    return ERROR_WITNESS_SIZE;
  }

  // compute message hash
  SHA3_CTX sha3_ctx;
  keccak_init(&sha3_ctx);
  keccak_update(&sha3_ctx, message, DATE_SIZE);
  keccak_final(&sha3_ctx, origin);

  // compute personal message hash
  keccak_init(&sha3_ctx);
  unsigned char eth_prefix[28] = {0x19, 0x45, 0x74, 0x68, 0x65, 0x72, 0x65,
                                  0x75, 0x6d, 0x20, 0x53, 0x69, 0x67, 0x6e,
                                  0x65, 0x64, 0x20, 0x4d, 0x65, 0x73, 0x73,
                                  0x61, 0x67, 0x65, 0x3a, 0x0a, 0x33, 0x32};
  keccak_update(&sha3_ctx, eth_prefix, 28);
  keccak_update(&sha3_ctx, origin, 32);
  keccak_final(&sha3_ctx, origin);

  return verify_signature(origin, signature, eth_address);
}

int main() {
  unsigned char buffer[DATE_SIZE];

  uint64_t len = DATE_SIZE;
  int ret = 0;
  ret = ckb_load_cell_data(&buffer, &len, 0, 1, CKB_SOURCE_OUTPUT);
  if (ret == CKB_INDEX_OUT_OF_BOUND) {
    return ERROR_OUTPUT;
  }
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  if (len != DATE_SIZE) {
    return ERROR_ENCODING;
  }

  unsigned char eth_address[BLAKE160_SIZE];
  ret = read_args(eth_address);
  if (ret != CKB_SUCCESS) {
    return ret;
  }

  int input_size = ckb_calculate_inputs_len();
  if (input_size == 0) {
    return 0;
  }
  return verify_secp256k1_keccak_sighash_all(buffer, eth_address);
}
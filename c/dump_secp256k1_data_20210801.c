#include <stdio.h>
#include "blake2b.h"

/*
 * We are including secp256k1 implementation directly so gcc can strip
 * unused functions. For some unknown reasons, if we link in libsecp256k1.a
 * directly, the final binary will include all functions rather than those used.
 */
#include "precomputed_ecmult.c"

#define ERROR_IO -1

int main(int argc, char* argv[]) {
  size_t pre_size = sizeof(secp256k1_pre_g);
  size_t pre128_size = sizeof(secp256k1_pre_g_128);

  FILE* fp_data = fopen("build/secp256k1_data_20210801", "wb");
  if (!fp_data) {
    return ERROR_IO;
  }
  fwrite(secp256k1_pre_g, pre_size, 1, fp_data);
  fwrite(secp256k1_pre_g_128, pre128_size, 1, fp_data);
  fclose(fp_data);

  FILE* fp = fopen("build/secp256k1_data_info_20210801.h", "w");
  if (!fp) {
    return ERROR_IO;
  }

  fprintf(fp, "#ifndef CKB_SECP256K1_DATA_INFO_H_\n");
  fprintf(fp, "#define CKB_SECP256K1_DATA_INFO_H_\n");
  fprintf(fp, "#define CKB_SECP256K1_DATA_SIZE %ld\n", pre_size + pre128_size);
  fprintf(fp, "#define CKB_SECP256K1_DATA_PRE_SIZE %ld\n", pre_size);
  fprintf(fp, "#define CKB_SECP256K1_DATA_PRE128_SIZE %ld\n", pre128_size);

  blake2b_state blake2b_ctx;
  uint8_t hash[32];
  blake2b_init(&blake2b_ctx, 32);
  blake2b_update(&blake2b_ctx, secp256k1_pre_g, pre_size);
  blake2b_update(&blake2b_ctx, secp256k1_pre_g_128, pre128_size);
  blake2b_final(&blake2b_ctx, hash, 32);

  fprintf(fp, "static uint8_t ckb_secp256k1_data_hash[32] = {\n  ");
  for (int i = 0; i < 32; i++) {
    fprintf(fp, "%u", hash[i]);
    if (i != 31) {
      fprintf(fp, ", ");
    }
  }
  fprintf(fp, "\n};\n");
  fprintf(fp, "#endif\n");
  fclose(fp);

  FILE* fp_inc = fopen("build/precomputed_ecmult.h", "wb");

  fprintf(fp_inc, "#ifndef SECP256K1_PRECOMPUTED_ECMULT_H\n");
  fprintf(fp_inc, "#define SECP256K1_PRECOMPUTED_ECMULT_H\n");

  fprintf(fp_inc, "#define WINDOW_G ECMULT_WINDOW_SIZE\n");
  fprintf(fp_inc, "extern secp256k1_ge_storage *secp256k1_pre_g;\n");
  fprintf(fp_inc, "extern secp256k1_ge_storage *secp256k1_pre_g_128;\n");

  fprintf(fp_inc, "#endif /* SECP256K1_PRECOMPUTED_ECMULT_H */\n");

  fclose(fp_inc);

  return 0;
}

#ifndef __MOLECULE2_VERIFY_H__
#define __MOLECULE2_VERIFY_H__

#include "molecule2_reader.h"

int verify_BytesOpt(const mol2_cursor_t cur) {
  // TODO
  return 0;
}

int verify_WitnessArgs(mol2_cursor_t cur) {
  int err = 0;

  WitnessArgsType table = make_WitnessArgs(&cur);
  BytesOptType lock = table.t->lock(&table);
  err = verify_BytesOpt(lock.cur);
  if (err) return err;
  BytesOptType input_type = table.t->input_type(&table);
  err = verify_BytesOpt(input_type.cur);
  if (err) return err;
  BytesOptType output_type = table.t->output_type(&table);
  err = verify_BytesOpt(output_type.cur);
  if (err) return err;

  return err;
}

int verify_WitnessLayout(mol2_cursor_t cur) {
  // TODO
  return 0;
}

#endif

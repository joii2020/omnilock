#ifndef __MOLECULE2_VERIFY_H__
#define __MOLECULE2_VERIFY_H__

#include "molecule2_reader.h"


#define SCRIPT_HASH_SIZE 32

typedef enum WitnessLayoutId {
  WitnessLayoutSighashAll = 4278190081,
  WitnessLayoutSighashAllOnly = 4278190082,
  WitnessLayoutOtx = 4278190083,
  WitnessLayoutOtxStart = 4278190084,
} WitnessLayoutId;

// If it is get by other struct, not need to verify
int verify_Bytes(mol2_cursor_t cur) {
  BytesType bytes = make_Bytes(&cur);
  uint32_t len = bytes.t->len(&bytes);
  for (uint32_t i = 0; i < len; i++) {
    bool existing = false;
    bytes.t->get(&bytes, i, &existing);
    if (!existing) return MOL2_ERR;
  }
  return 0;
}

int verify_BytesOpt(mol2_cursor_t cur) {
  BytesOptType bytes_opt = make_BytesOpt(&cur);

  if (bytes_opt.t->is_some(&bytes_opt)) {
    bytes_opt.t->unwrap(&bytes_opt);
  }
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

int verify_Action(ActionType *action) {
  printf("verify Action");
  printf("---- cur.size: %d, cur.offse: %d", action->cur.size,
         action->cur.offset);
  action->t->data(action);
  
  // mol2_verify_fixed_size(&data, SCRIPT_HASH_SIZE);
  mol2_cursor_t script_hash = action->t->script_hash(action);
  mol2_verify_fixed_size(&script_hash, SCRIPT_HASH_SIZE);
  mol2_cursor_t script_info_hash = action->t->script_info_hash(action);
  mol2_verify_fixed_size(&script_info_hash, SCRIPT_HASH_SIZE);

  return 0;
}

int verify_ActionVec(ActionVecType *actions) {
  printf("verify ActionVec");
  int err = 0;
  uint32_t len = actions->t->len(actions);
  for (uint32_t i = 0; i < len; i++) {
    bool existing = false;
    ActionType action = actions->t->get(actions, i, &existing);
    if (!existing) return MOL2_ERR;

    err = verify_Action(&action);
    if (err) return err;
  }

  return 0;
}

int verify_Message(MessageType *message) {
  printf("verify Message");

  ActionVecType actions = message->t->actions(message);
  int err = verify_ActionVec(&actions);
  if (err) return err;

  return 0;
}

int verify_SealPair(SealPairType seal_pair) {
  int err = 0;
  mol2_cursor_t script_hash = seal_pair.t->script_hash(&seal_pair);
  err = mol2_verify_fixed_size(&script_hash, SCRIPT_HASH_SIZE);
  if (err != MOL2_OK) return MOL2_ERR_DATA;

  seal_pair.t->seal(&seal_pair);

  return 0;
}

int verify_SealPairVec(SealPairVecType seals) {
  printf("verify SealPairVec");

  int err = 0;
  uint32_t len = seals.t->len(&seals);
  for (uint32_t i = 0; i < len; i++) {
    bool existing = false;
    SealPairType seal_pair = seals.t->get(&seals, i, &existing);
    if (!existing) return MOL2_ERR_DATA;

    err = verify_SealPair(seal_pair);
    if (err) return err;
  }

  return 0;
}

int verify_SighashAll(mol2_cursor_t cur) {
  printf("verify SighashAll");

  SighashAllType sighash_all = make_SighashAll(&cur);
  MessageType message = sighash_all.t->message(&sighash_all);
  int err = verify_Message(&message);
  if (err) return err;

  sighash_all.t->seal(&sighash_all);
  return 0;
}

int verify_SighashAllOnly(mol2_cursor_t cur) {
  printf("verify SighashAllOnly");

  SighashAllOnlyType signhash_all_only = make_SighashAllOnly(&cur);
  signhash_all_only.t->seal(&signhash_all_only);

  return 0;
}

int verify_Otx(mol2_cursor_t cur) {
  printf("verify Otx");

  OtxType otx = make_Otx(&cur);

  Otx_get_input_cells_impl(&otx);
  Otx_get_output_cells_impl(&otx);
  Otx_get_cell_deps_impl(&otx);
  Otx_get_header_deps_impl(&otx);
  MessageType message = Otx_get_message_impl(&otx);
  int err = verify_Message(&message);
  if (err) return err;
  SealPairVecType seals = Otx_get_seals_impl(&otx);
  err = verify_SealPairVec(seals);
  if (err) return err;

  return 0;
}

int verify_OtxStart(mol2_cursor_t cur) {
  printf("verify OtxStart");

  OtxStartType otx_start = make_OtxStart(&cur);

  otx_start.t->start_input_cell(&otx_start);
  otx_start.t->start_output_cell(&otx_start);
  otx_start.t->start_cell_deps(&otx_start);
  otx_start.t->start_header_deps(&otx_start);

  return 0;
}

int get_union_id(mol2_cursor_t *cur, uint32_t *union_id) {
  uint32_t len = mol2_read_at(cur, (uint8_t *)union_id, MOL2_NUM_T_SIZE);
  if (len != MOL2_NUM_T_SIZE) {
    return MOL2_ERR_DATA;
  }

  return 0;
}

int verify_WitnessLayout(mol2_cursor_t cur) {
  printf("verify WitnessLayout");

  int err = 0;
  uint32_t union_id = 0;
  err = get_union_id(&cur, &union_id);
  if (err) return err;

  // If use mol2_union_unpack, panic may be hit, causing problems in other code.
  mol2_cursor_t union_item = cur;
  union_item.offset = cur.offset + MOL2_NUM_T_SIZE;
  union_item.size = cur.size - MOL2_NUM_T_SIZE;

  // TODO testcase
  switch (union_id) {
    case WitnessLayoutSighashAll:
      return verify_SighashAll(union_item);
    case WitnessLayoutSighashAllOnly:
      return verify_SighashAllOnly(union_item);
    case WitnessLayoutOtx:
      return verify_Otx(union_item);
    case WitnessLayoutOtxStart:
      return verify_OtxStart(union_item);
    default:
      printf("error: unknow WitnessLayout id: %ux", union_id);
      return MOL2_ERR_DATA;
  }
}

#endif

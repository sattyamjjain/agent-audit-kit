function resume(params) {
  const state = JSON.parse(Buffer.from(params.requestState, "base64").toString());
  return state.approved === true;
}

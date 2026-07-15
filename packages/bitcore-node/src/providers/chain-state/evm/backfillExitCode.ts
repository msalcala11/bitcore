export interface BackfillExitState {
  fatal?: boolean;
  skippedTransactions?: number;
  unwrittenTransactions?: number;
  interrupted?: boolean;
}

export function computeBackfillExitCode(state: BackfillExitState): 0 | 1 | 2 {
  if (state.fatal) {
    return 1;
  }
  if (state.interrupted || (state.skippedTransactions || 0) > 0 || (state.unwrittenTransactions || 0) > 0) {
    return 2;
  }
  return 0;
}

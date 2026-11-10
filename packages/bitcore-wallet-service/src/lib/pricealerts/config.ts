export const PRICE_ALERT_DEFAULTS = {
  enabled: false,
  workerEnabled: false,
  pollIntervalMs: 60000,
  maxSourceAgeMs: 300000,
  coinGeckoBatchSize: 100,
  brazeTimeoutMs: 10000,
  brazeConcurrency: 2,
  maxEnabledRules: 50,
  campaignId: '',
  appleMessageVariationId: '',
  androidMessageVariationId: ''
};

export type PriceAlertOptions = typeof PRICE_ALERT_DEFAULTS;

export function priceAlertOptions(opts: Partial<PriceAlertOptions> = {}): PriceAlertOptions {
  const result = { ...PRICE_ALERT_DEFAULTS, ...opts };
  for (const key of ['enabled', 'workerEnabled']) {
    if (typeof result[key] !== 'boolean') throw new Error(`priceAlertsOpts.${key} must be boolean`);
  }
  for (const key of ['pollIntervalMs', 'maxSourceAgeMs', 'coinGeckoBatchSize', 'brazeTimeoutMs', 'brazeConcurrency', 'maxEnabledRules']) {
    if (!Number.isSafeInteger(result[key]) || result[key] <= 0) {
      throw new Error(`priceAlertsOpts.${key} must be a positive integer`);
    }
  }
  if (result.coinGeckoBatchSize > 515) throw new Error('priceAlertsOpts.coinGeckoBatchSize must be <= 515');
  for (const key of ['campaignId', 'appleMessageVariationId', 'androidMessageVariationId']) {
    if (typeof result[key] !== 'string' || result[key].length > 256) throw new Error(`Invalid priceAlertsOpts.${key}`);
  }
  return result;
}

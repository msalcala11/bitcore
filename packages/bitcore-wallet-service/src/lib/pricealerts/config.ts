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

export function validatePriceAlertBrazeSettings(settings?: { pushServerUrlBraze?: unknown; authorizationKeyBraze?: unknown }): void {
  try {
    const url = settings?.pushServerUrlBraze;
    if (typeof url !== 'string' || !/^https?:\/\//i.test(url)) throw new Error();
    const parsed = new URL(url);
    if (!['http:', 'https:'].includes(parsed.protocol) || !parsed.hostname) throw new Error();
  } catch {
    throw new Error('pushNotificationsOpts.pushServerUrlBraze must be an absolute HTTP or HTTPS URL');
  }
  const key = settings?.authorizationKeyBraze;
  if (typeof key !== 'string' || !key.trim() || key.trim().toLowerCase() === 'you_have_to_put_something_here') {
    throw new Error('pushNotificationsOpts.authorizationKeyBraze must be a nonempty, non-placeholder string');
  }
}

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

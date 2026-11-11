import { CoinGeckoService, canonicalCoinGeckoAsset } from '../../externalservices/coingecko';
import { Defaults } from '../common/defaults';
import { ClientError } from '../errors/clienterror';
import type { PriceAlertOptions } from './config';
import type { PriceAlertStorage } from './storage';
import type { PriceAlertRegistration, PriceAlertRule } from '../model/pricealert';

const registrationFields = ['externalUserId', 'priceAlertsEnabled', 'pushEnabled'];

function fieldsOnly(value: Record<string, unknown>, allowed: string[]) {
  if (Object.keys(value).some(key => !allowed.includes(key))) throw new ClientError('BADREQUEST', 'Unsupported field');
}

function publicRegistration(registration: PriceAlertRegistration) {
  return registration ? {
    registered: true, externalUserId: registration.externalUserId,
    priceAlertsEnabled: registration.priceAlertsEnabled, pushEnabled: registration.pushEnabled
  } : { registered: false };
}

function publicRule(rule: PriceAlertRule) {
  return {
    assetKey: rule.assetKey, ...(rule.coin ? { coin: rule.coin } : {}),
    ...(rule.chain ? { chain: rule.chain, tokenAddress: rule.tokenAddress } : {}),
    name: rule.name, symbol: rule.symbol, thresholdPct: rule.thresholdPct, code: rule.code
  };
}

export class PriceAlertService {
  constructor(private storage: PriceAlertStorage, private provider: CoinGeckoService, private options: PriceAlertOptions) {}

  async register(ownerId: string, body: Record<string, unknown>) {
    fieldsOnly(body, registrationFields);
    if ('externalUserId' in body && (typeof body.externalUserId !== 'string' ||
        !body.externalUserId.trim() || body.externalUserId.length > 256 || [...body.externalUserId].some(character => character.charCodeAt(0) < 32 || character.charCodeAt(0) === 127))) {
      throw new ClientError('BADREQUEST', 'externalUserId must be a nonempty string of at most 256 characters');
    }
    for (const field of ['priceAlertsEnabled', 'pushEnabled']) {
      if (field in body && typeof body[field] !== 'boolean') throw new ClientError('BADREQUEST', `${field} must be boolean`);
    }
    const registration = await this.storage.getRegistration(ownerId);
    if (!registration && registrationFields.some(field => !(field in body))) {
      throw new ClientError('BADREQUEST', 'Initial registration requires externalUserId, priceAlertsEnabled and pushEnabled');
    }
    if (Object.keys(body).length) await this.storage.saveRegistration(ownerId, body);
    return publicRegistration(await this.storage.getRegistration(ownerId));
  }

  async list(ownerId: string) {
    const registration = await this.storage.getRegistration(ownerId);
    const rules = await this.storage.listRules(ownerId);
    return { registration: publicRegistration(registration), alerts: rules.map(publicRule) };
  }

  private validateSelector(query: Record<string, unknown>, disabling = false) {
    fieldsOnly(query, ['coin', 'chain', 'tokenAddress']);
    for (const [key, value] of Object.entries(query)) {
      if (disabling && key === 'coin' && query.tokenAddress) continue;
      if (typeof value !== 'string' || !value.trim()) throw new ClientError('BADREQUEST', `Invalid ${key}`);
    }
    return canonicalCoinGeckoAsset(query, disabling);
  }

  async save(ownerId: string, query: Record<string, unknown>, body: Record<string, unknown>) {
    fieldsOnly(body, ['thresholdPct', 'code']);
    if (![5, 10, 15, 20].includes(body.thresholdPct as number)) throw new ClientError('BADREQUEST', 'Invalid thresholdPct');
    const code = typeof body.code === 'string' ? body.code.toUpperCase() : '';
    if (!Defaults.FIAT_CURRENCIES.some(fiat => fiat.code === code)) throw new ClientError('BADREQUEST', 'Unsupported fiat code');
    const selector = this.validateSelector(query);
    if (!await this.storage.getRegistration(ownerId)) throw new ClientError('PRICE_ALERTS_UNREGISTERED', 'Register before saving alerts');
    const current = await this.storage.getRule(ownerId, selector.assetKey);
    if (!current?.enabled && await this.storage.countEnabledRules(ownerId) >= this.options.maxEnabledRules) {
      throw new ClientError('PRICE_ALERTS_LIMIT', 'Maximum enabled price alerts reached');
    }
    // Metadata is captured at creation, not silently refreshed on identical retries.
    const storedAsset = current ? {
      ...selector, providerId: current.providerId, name: current.name, symbol: current.symbol
    } : await this.provider.resolvePriceAlertAsset(query);
    if (storedAsset.tokenAddress) delete storedAsset.coin;
    await this.storage.saveRule(ownerId, storedAsset, body.thresholdPct as number, code);
    return publicRule(await this.storage.getRule(ownerId, selector.assetKey));
  }

  async disable(ownerId: string, query: Record<string, unknown>) {
    const asset = this.validateSelector(query, true);
    await this.storage.disableRule(ownerId, asset.assetKey);
    return { disabled: true };
  }
}

import { createHash } from 'crypto';
import logger from '../logger';
import { priceAlertSetForOwner } from '../model/pricealert';
import type { PriceAlertOptions } from './config';
import type { PriceAlertDelivery, ReservedPriceAlert } from './delivery';
import type { PriceAlertStorage } from './storage';
import type { CoinGeckoService } from '../../externalservices/coingecko';
import type { PriceAlertObservation } from '../model/pricealert';

const FUTURE_TOLERANCE_MS = 30000;
type ScanOutcome = 'error' | 'stale' | 'capped' | 'complete';
type PollOutcome = 'error' | 'idle' | 'complete';

export function readPriceObservation(providerId: string, code: string, data, now: number, maxAge: number): { observation?: PriceAlertObservation; reason?: string } {
  const currency = code.toLowerCase();
  const price = data?.[currency];
  const change24hPct = data?.[`${currency}_24h_change`];
  const seconds = data?.last_updated_at;
  if (typeof price !== 'number' || !Number.isFinite(price) || price <= 0) return { reason: 'invalid_price' };
  if (typeof change24hPct !== 'number' || !Number.isFinite(change24hPct)) return { reason: 'invalid_change' };
  if (typeof seconds !== 'number' || !Number.isFinite(seconds) || seconds <= 0 || !Number.isSafeInteger(seconds * 1000)) {
    return { reason: 'invalid_timestamp' };
  }
  const observedAt = seconds * 1000;
  if (observedAt > now + FUTURE_TOLERANCE_MS) return { reason: 'future' };
  if (now - observedAt > maxAge) return { reason: 'stale' };
  const id = createHash('sha256').update(JSON.stringify([providerId, code, observedAt, price, change24hPct])).digest('hex');
  return { observation: { id, providerId, code, price, change24hPct, observedAt } };
}

export class PriceAlertWorker {
  // Bounds are per market/currency turn and count reservations, never skipped owners.
  pageSize = 100;
  maxReservationsPerMarket = 1000;
  private positions = new Map<string, string>();
  private nextMarket = 0;
  private running = false;
  private timer: NodeJS.Timeout;
  private stopped = true;

  constructor(private storage: PriceAlertStorage, private provider: CoinGeckoService,
    private delivery: PriceAlertDelivery, private options: PriceAlertOptions) {}

  start() {
    if (!this.stopped) return;
    this.stopped = false;
    if (!this.options.enabled || !this.options.workerEnabled) logger.info('Price alert worker disabled; staying idle');
    const tick = async () => {
      const startedAt = Date.now();
      const outcome = await this.poll();
      const delay = outcome === 'complete'
        ? Math.max(0, startedAt + this.options.pollIntervalMs - Date.now())
        : this.options.pollIntervalMs;
      if (!this.stopped) this.timer = setTimeout(tick, delay);
    };
    void tick();
  }

  stop() {
    this.stopped = true;
    clearTimeout(this.timer);
  }

  async poll(): Promise<PollOutcome> {
    if (this.running || !this.options.enabled || !this.options.workerEnabled) return 'idle';
    this.running = true;
    const reasons: Record<string, number> = {};
    const skip = (reason: string) => { reasons[reason] = (reasons[reason] || 0) + 1; };
    try {
      const discovered = await this.storage.markets();
      const active = new Set(discovered.map(market => `${market.providerId}:${market.code}`));
      for (const key of this.positions.keys()) if (!active.has(key)) this.positions.delete(key);
      if (!discovered.length) return 'idle';
      // Rotate before grouping IDs so each market also gets a turn at fresh acquisition.
      const first = this.nextMarket++ % discovered.length;
      const markets = discovered.slice(first).concat(discovered.slice(0, first));
      const ids = [...new Set(markets.map(market => market.providerId))];
      const codes = [...new Set(markets.map(market => market.code))];
      let continuations: PriceAlertObservation[] = [];
      // At most two provider requests in flight. Traffic depends only on markets.
      for (let i = 0; i < ids.length; i += this.options.coinGeckoBatchSize * 2) {
        const batches = [ids.slice(i, i + this.options.coinGeckoBatchSize),
          ids.slice(i + this.options.coinGeckoBatchSize, i + 2 * this.options.coinGeckoBatchSize)].filter(batch => batch.length);
        const results = await Promise.all(batches.map(async batch => {
          try {
            return { batch, data: await this.provider.priceAlertPrices(batch, codes) };
          } catch (err) {
            skip(err?.statusCode === 429 ? 'provider_429' : /TIME|TIMEDOUT/.test(err?.code || '') ? 'provider_timeout' : 'provider_error');
            return { batch, data: undefined };
          }
        }));
        for (const { batch, data } of results) {
          if (!data) { skip('invalid_response'); continue; }
          for (const market of markets.filter(m => batch.includes(m.providerId))) {
            const { observation, reason } = readPriceObservation(market.providerId, market.code,
              data[market.providerId], Date.now(), this.options.maxSourceAgeMs);
            if (reason) { skip(reason); continue; }
            if (Math.abs(observation.change24hPct) < 5) { skip('below_threshold'); continue; }
            const outcome = await this.scan(observation, skip);
            if (outcome === 'error') return 'error';
            if (outcome === 'capped') continuations.push(observation);
          }
        }
      }
      // Every provider batch has had its first round. Retain one original
      // observation per capped market/currency; continuations never fetch prices.
      while (continuations.length) {
        const next: PriceAlertObservation[] = [];
        for (const observation of continuations) {
          const outcome = await this.scan(observation, skip);
          if (outcome === 'error') return 'error';
          if (outcome === 'capped') next.push(observation);
        }
        continuations = next;
      }
      return 'complete';
    } catch (err) {
      skip('poll_error');
      logger.error('Price alert poll stopped: %o', { message: err?.message });
      return 'error';
    } finally {
      if (Object.keys(reasons).length) logger.info('Price alert skipped evaluations: %o', reasons);
      this.running = false;
    }
  }

  private async scan(observation: PriceAlertObservation, skip: (reason: string) => void): Promise<ScanOutcome> {
    const key = `${observation.providerId}:${observation.code}`;
    const start = this.positions.get(key);
    let after = start;
    let wrapped = false;
    let outcome: ScanOutcome = 'complete';
    const reserved: ReservedPriceAlert[] = [];
    try {
      scan: while (reserved.length < this.maxReservationsPerMarket) {
        if (Date.now() - observation.observedAt > this.options.maxSourceAgeMs) {
          outcome = 'stale';
          skip('stale_during_scan');
          break;
        }
        const page = await this.storage.candidates(observation, Date.now(), after, wrapped ? start : undefined, this.pageSize);
        if (!page.length) {
          if (!wrapped && start) { after = undefined; wrapped = true; continue; }
          this.positions.delete(key);
          break;
        }
        const registrations = await this.storage.registrationsForRules(page);
        const bySet = new Map(registrations.map(registration => [priceAlertSetForOwner(registration._id), registration]));
        for (const rule of page) {
          // Leave the cursor BEFORE this candidate if freshness/bounds stop us.
          const now = Date.now();
          if (now - observation.observedAt > this.options.maxSourceAgeMs) {
            outcome = 'stale';
            skip('stale_during_scan');
            break scan;
          }
          if (reserved.length >= this.maxReservationsPerMarket) break scan;
          const registration = bySet.get(rule.alertSetId);
          if (!registration || registration.alertSetId !== rule.alertSetId) skip('unregistered');
          else if (!registration.priceAlertsEnabled) skip('paused');
          else if (!registration.pushEnabled) skip('push_ineligible');
          else if (await this.storage.reserve(rule, observation, now)) {
            reserved.push({ rule, observation, externalUserId: registration.externalUserId });
          } else skip('reservation_conflict');
          after = rule._id;
          this.positions.set(key, after);
        }
      }
      if (outcome !== 'stale' && reserved.length >= this.maxReservationsPerMarket) outcome = 'capped';
    } catch (err) {
      outcome = 'error';
      skip('storage_error');
      logger.error('Price alert reservations stopped for this poll: %o', { message: err?.message });
    }
    // Even when the next reservation fails or the observation ages, already
    // acknowledged reservations get their one attempt. Nothing releases cooldowns.
    await this.delivery.send(reserved);
    return outcome;
  }
}

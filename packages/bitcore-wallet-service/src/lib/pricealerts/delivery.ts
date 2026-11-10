import request from 'request';
import logger from '../logger';
import type { PriceAlertOptions } from './config';
import type { PriceAlertObservation, PriceAlertRule } from '../model/pricealert';

export interface ReservedPriceAlert {
  rule: PriceAlertRule;
  observation: PriceAlertObservation;
  externalUserId: string;
}

export function priceAlertMessage(rule: PriceAlertRule, observation: PriceAlertObservation, sentAt: number) {
  const title = `Price Alert: ${rule.name}`;
  const body = `${rule.name} has moved ${rule.thresholdPct}%. View the latest price.`;
  const routing = {
    currencyAbbreviation: rule.coin || rule.symbol.toLowerCase(),
    ...(rule.chain ? { chain: rule.chain, tokenAddress: rule.tokenAddress } : {})
  };
  const extra = {
    notification_type: 'price_alert', assetKey: rule.assetKey, ...routing,
    name: rule.name, symbol: rule.symbol, thresholdPct: rule.thresholdPct,
    change24hPct: observation.change24hPct, direction: observation.change24hPct < 0 ? 'down' : 'up',
    code: rule.code, price: observation.price, observedAt: observation.observedAt,
    sentAt, observationId: observation.id
  };
  const query = new URLSearchParams({ ...routing, notification_type: 'price_alert', code: rule.code });
  const custom_uri = `bitpay://exchange-rate?${query.toString()}`;
  return {
    apple_push: { alert: { title, body }, extra, custom_uri },
    android_push: { alert: body, title, extra, custom_uri }
  };
}

export class PriceAlertDelivery {
  request = request;

  constructor(private options: PriceAlertOptions, private pushOptions: { pushServerUrlBraze?: string; authorizationKeyBraze?: string }) {}

  async send(reservations: ReservedPriceAlert[]) {
    const groups = new Map<string, ReservedPriceAlert[]>();
    for (const item of reservations) {
      const key = JSON.stringify(priceAlertMessage(item.rule, item.observation, 0));
      const group = groups.get(key) || [];
      group.push(item);
      groups.set(key, group);
    }
    const batches: ReservedPriceAlert[][] = [];
    for (const group of groups.values()) {
      let batch: ReservedPriceAlert[] = [];
      for (const item of group) {
        // Keep independent reservations for one destination in separate requests.
        if (batch.length === 50 || batch.some(other => other.externalUserId === item.externalUserId)) {
          batches.push(batch);
          batch = [];
        }
        batch.push(item);
      }
      if (batch.length) batches.push(batch);
    }
    let next = 0;
    await Promise.all(Array.from({ length: Math.min(this.options.brazeConcurrency, batches.length) }, async () => {
      while (next < batches.length) await this.sendBatch(batches[next++]);
    }));
  }

  private sendBatch(batch: ReservedPriceAlert[]): Promise<void> {
    const messages: any = priceAlertMessage(batch[0].rule, batch[0].observation, Date.now());
    if (this.options.appleMessageVariationId) messages.apple_push.message_variation_id = this.options.appleMessageVariationId;
    if (this.options.androidMessageVariationId) messages.android_push.message_variation_id = this.options.androidMessageVariationId;
    const body = {
      external_user_ids: batch.map(item => item.externalUserId), messages,
      ...(this.options.campaignId ? { campaign_id: this.options.campaignId } : {})
    };
    return new Promise(resolve => {
      const done = (err, response?, responseBody?) => {
        const data = responseBody ?? response?.body;
        const status = response?.statusCode;
        const accepted = !err && status >= 200 && status < 300 && data?.message === 'success' && !data?.errors?.length;
        logger.info('Price alert Braze outcome: %o', {
          outcome: err ? 'unknown' : accepted ? 'accepted' : 'rejected',
          status, recipients: batch.length, dispatchId: data?.dispatch_id,
          error: err?.code, message: data?.message
        });
        resolve();
      };
      try {
        this.request({
          url: this.pushOptions.pushServerUrlBraze?.replace(/\/$/, '') + '/messages/send',
          method: 'POST', json: true, timeout: this.options.brazeTimeoutMs,
          // Prevent redirect handling from issuing another delivery request.
          followRedirect: false,
          headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + this.pushOptions.authorizationKeyBraze },
          body
        }, done);
      } catch (err) {
        done(err);
      }
    });
  }
}

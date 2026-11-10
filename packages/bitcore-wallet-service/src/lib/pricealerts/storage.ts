import { createHash } from 'crypto';
import { priceAlertSetForOwner } from '../model/pricealert';
import type { PriceAlertObservation, PriceAlertRegistration, PriceAlertRule, ResolvedPriceAlertAsset } from '../model/pricealert';
import type { Db } from 'mongodb';

export const PRICE_ALERT_COLLECTIONS = {
  PRICE_ALERT_REGISTRATIONS: 'price_alert_registrations',
  PRICE_ALERT_RULES: 'price_alert_rules'
};

export const PRICE_ALERT_COOLDOWN_MS = 24 * 60 * 60 * 1000;

export class PriceAlertStorage {
  constructor(private db: Db) {}

  private get registrations() {
    return this.db.collection<PriceAlertRegistration>(PRICE_ALERT_COLLECTIONS.PRICE_ALERT_REGISTRATIONS);
  }

  private get rules() {
    return this.db.collection<PriceAlertRule>(PRICE_ALERT_COLLECTIONS.PRICE_ALERT_RULES);
  }

  static async createIndexes(db: Db) {
    const rules = db.collection(PRICE_ALERT_COLLECTIONS.PRICE_ALERT_RULES);
    await Promise.all([
      rules.createIndex({ alertSetId: 1, enabled: 1 }),
      rules.createIndex({ enabled: 1, providerId: 1, code: 1, _id: 1, thresholdPct: 1, nextEligibleAt: 1 })
    ]);
  }

  private ruleId(alertSetId: string, assetKey: string): string {
    return createHash('sha256').update(JSON.stringify([alertSetId, assetKey])).digest('hex');
  }

  // MongoDB 3.6 does not retry concurrent-upsert duplicate keys. The changed-only
  // predicate also deliberately collides on identical retries; then update without
  // upsert, preserving updatedAt. _id guarantees uniqueness before indexes finish.
  private async upsertChanged(collection, id: string, fields, inserted) {
    const filter = { _id: id, $or: Object.entries(fields).map(([key, value]) => ({ [key]: { $ne: value } })) };
    const update = { $set: { ...fields, updatedAt: Date.now() }, $setOnInsert: { ...inserted, createdAt: Date.now() } };
    try {
      await collection.updateOne(filter, update, { upsert: true });
    } catch (err) {
      if (err.code !== 11000) throw err;
      await collection.updateOne(filter, update);
    }
  }

  getRegistration(ownerId: string): Promise<PriceAlertRegistration> {
    return this.registrations.findOne({ _id: ownerId, alertSetId: priceAlertSetForOwner(ownerId) }, { readPreference: 'primary' });
  }

  async saveRegistration(ownerId: string, fields: Partial<PriceAlertRegistration>) {
    await this.upsertChanged(this.registrations, ownerId, fields, { alertSetId: priceAlertSetForOwner(ownerId) });
  }

  listRules(ownerId: string): Promise<PriceAlertRule[]> {
    return this.rules.find({ alertSetId: priceAlertSetForOwner(ownerId), enabled: true }, { readPreference: 'primary' })
      .sort({ _id: 1 }).toArray();
  }

  getRule(ownerId: string, assetKey: string): Promise<PriceAlertRule> {
    const alertSetId = priceAlertSetForOwner(ownerId);
    return this.rules.findOne({ _id: this.ruleId(alertSetId, assetKey), alertSetId }, { readPreference: 'primary' });
  }

  countEnabledRules(ownerId: string): Promise<number> {
    return this.rules.countDocuments({ alertSetId: priceAlertSetForOwner(ownerId), enabled: true }, { readPreference: 'primary' });
  }

  async saveRule(ownerId: string, asset: ResolvedPriceAlertAsset, thresholdPct: number, code: string) {
    const alertSetId = priceAlertSetForOwner(ownerId);
    // Never replace a document: the cooldown is independent of configuration.
    await this.upsertChanged(this.rules, this.ruleId(alertSetId, asset.assetKey),
      { ...asset, thresholdPct, code, enabled: true }, { alertSetId });
  }

  async disableRule(ownerId: string, assetKey: string) {
    const alertSetId = priceAlertSetForOwner(ownerId);
    await this.rules.updateOne({ _id: this.ruleId(alertSetId, assetKey), alertSetId, enabled: true },
      { $set: { enabled: false, updatedAt: Date.now() } });
  }

  markets(): Promise<Array<{ providerId: string; code: string }>> {
    return this.rules.aggregate([
      { $match: { enabled: true } },
      { $group: { _id: { providerId: '$providerId', code: '$code' } } },
      { $replaceRoot: { newRoot: '$_id' } },
      { $sort: { providerId: 1, code: 1 } }
    ], { readPreference: 'primary' }).toArray();
  }

  candidates(observation: PriceAlertObservation, now: number, after: string | undefined, through: string | undefined, limit: number): Promise<PriceAlertRule[]> {
    const filter: any = {
      enabled: true, providerId: observation.providerId, code: observation.code,
      thresholdPct: { $lte: Math.abs(observation.change24hPct) },
      $or: [{ nextEligibleAt: { $exists: false } }, { nextEligibleAt: { $lte: now } }]
    };
    if (after || through) filter._id = { ...(after ? { $gt: after } : {}), ...(through ? { $lte: through } : {}) };
    return this.rules.find(filter, { readPreference: 'primary' }).sort({ _id: 1 }).limit(limit).toArray();
  }

  registrationsForRules(rules: PriceAlertRule[]): Promise<PriceAlertRegistration[]> {
    // v1 has one owner per set. Still resolve owner -> set in the common function.
    return this.registrations.find({ _id: { $in: [...new Set(rules.map(rule => rule.alertSetId))] } },
      { readPreference: 'primary' }).toArray();
  }

  async reserve(rule: PriceAlertRule, observation: PriceAlertObservation, now: number): Promise<boolean> {
    const result = await this.rules.updateOne({
      _id: rule._id, alertSetId: rule.alertSetId, enabled: true,
      thresholdPct: rule.thresholdPct, code: rule.code, providerId: rule.providerId,
      $or: [{ nextEligibleAt: { $exists: false } }, { nextEligibleAt: { $lte: now } }]
    }, { $set: { nextEligibleAt: now + PRICE_ALERT_COOLDOWN_MS, lastReservedAt: now, lastObservation: observation } });
    // No write-concern override. w:0, write concern errors, and ambiguous results
    // must fail closed. The caller stops reservations for the rest of this poll.
    if (result?.result?.ok !== 1 || result.result['writeConcernError'] ||
        typeof result.matchedCount !== 'number' || typeof result.modifiedCount !== 'number') {
      throw new Error('Price alert reservation was not positively acknowledged');
    }
    if (result.matchedCount === 0 && result.modifiedCount === 0) return false;
    if (result.matchedCount !== 1 || result.modifiedCount !== 1) throw new Error('Uncertain price alert reservation');
    return true;
  }
}

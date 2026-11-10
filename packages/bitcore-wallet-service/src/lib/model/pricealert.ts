export interface PriceAlertAsset {
  assetKey: string;
  coin?: string;
  chain?: string;
  tokenAddress?: string;
}

export interface ResolvedPriceAlertAsset extends PriceAlertAsset {
  providerId: string;
  name: string;
  symbol: string;
}

export interface PriceAlertRegistration {
  _id: string;
  alertSetId: string;
  externalUserId: string;
  priceAlertsEnabled: boolean;
  pushEnabled: boolean;
  createdAt: number;
  updatedAt: number;
}

export interface PriceAlertRule extends ResolvedPriceAlertAsset {
  _id: string;
  alertSetId: string;
  thresholdPct: number;
  code: string;
  enabled: boolean;
  createdAt: number;
  updatedAt: number;
  nextEligibleAt?: number;
  lastReservedAt?: number;
  lastObservation?: PriceAlertObservation;
}

export interface PriceAlertObservation {
  id: string;
  providerId: string;
  code: string;
  price: number;
  change24hPct: number;
  observedAt: number;
}

// The only owner -> set mapping. Destinations are deliberately not involved.
export function priceAlertSetForOwner(ownerId: string): string {
  return ownerId;
}

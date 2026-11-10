# App-owned price alerts

Price alerts use the app's existing `APP.identity[network]` signing key, independently
of wallets, copayers or BitPay accounts. Both feature and worker switches default to
off. Read the accepted limitations below before activation.

## HTTP and signing

Paths below are relative to the configured BWS mount (normally `/bws/api`). All four
require `x-identity` (hex secp256k1 public key) and `x-signature` (hex DER ECDSA signature).
JSON mutations require `Content-Type: application/json` and an object body.

| Method | Path | Body / result |
| --- | --- | --- |
| PUT | `/v1/pricealerts/registration/` | Initial `{ "externalUserId":"braze-id", "priceAlertsEnabled":true, "pushEnabled":true }`; later all fields optional |
| GET | `/v1/pricealerts/` | `{ "registration":{...}, "alerts":[...] }` |
| PUT | `/v1/pricealerts/?coin=btc` | `{ "thresholdPct":10, "code":"USD" }`; returns the saved rule's public fields |
| DELETE | `/v1/pricealerts/?coin=btc` | No body; returns `{ "disabled":true }`, including if already disabled or absent |

`externalUserId` is an asserted, mutable Braze destination (nonempty string, maximum
256 characters, no control characters). `pushEnabled` is the app's last-known general
push eligibility; `priceAlertsEnabled` is the separate Price Alerts pause preference.
Both must be booleans. A destination-only refresh changes neither preference. A
preference-only update leaves the destination unchanged. Empty updates of an existing
registration do nothing. Initial registration requires all three fields.

List returns only individually enabled rules, including when either preference is
false. Each contains `assetKey`, canonical selectors, `name`, `symbol`, `thresholdPct`
and `code`. It does not expose owner IDs, provider IDs, or cooldown diagnostics. An
unknown owner receives `{ "registration":{ "registered":false }, "alerts":[] }`;
listing creates nothing. Registration is required before saving rules.

The signed UTF-8 message is exactly:

```text
lowerCase(method) + "|" + apiRelativePathAndExactQueryString + "|" + JSON.stringify(bodyOrEmptyObject)
```

Use **one SHA-256**, secp256k1 ECDSA, DER encoding, then hex transport, as in BitAuth
0.4.1. BWS wallet signing uses double SHA-256 and does not work here. Both high-S and
low-S signatures verify after normalization. Compressed and uncompressed valid public
keys canonicalize to the same compressed key and owner (SHA-256 of its bytes).
The private key never reaches BWS. Existing wallet authentication remains unchanged.

Include the exact query encoding/order and trailing slash. Exclude origin and mount
prefix. Sign the parsed JSON object in its serialized property order before adding
business defaults. GET/DELETE with no body sign `{}`; arrays, scalars and null are not
valid mutation bodies. For example, this complete request uses the public throwaway
key in `test/fixtures/price-alert-signatures.json`:

```http
DELETE /bws/api/v1/pricealerts/?coin=btc HTTP/1.1
Host: bws.example.com
x-identity: 02fb4b3a1b3f7adbd3c322c41d07452f0fedd0ded9c427dcf155f2924e3e30691a
x-signature: 30440220538d6d6136735a408cdf51e2134f43613c649c6920d6f9a2057fc41d0586355f02201c52da27c4f2b171deb425e3e73cc1aa6cd79f804fc27a5256286f3bba8a3ebf

```

There is no HTTP body. Its signing message is `delete|/v1/pricealerts/?coin=btc|{}`.
Changing the query to `coin=eth` invalidates that signature. A Node signing example
(the app can keep using its existing BitAuth wrapper):

```js
const { createHash } = require('crypto');
const secp256k1 = require('secp256k1');
const method = 'PUT';
const relativePath = '/v1/pricealerts/?chain=eth&tokenAddress=0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48';
const body = { thresholdPct: 10, code: 'USD' };
const message = method.toLowerCase() + '|' + relativePath + '|' + JSON.stringify(body);
// privateKey is the app's existing 32-byte key, kept on the client.
const digest = createHash('sha256').update(message, 'utf8').digest();
const signature = Buffer.from(secp256k1.signatureExport(
  secp256k1.ecdsaSign(digest, privateKey).signature
)).toString('hex');
const identity = Buffer.from(secp256k1.publicKeyCreate(privateKey, true)).toString('hex');
// Send JSON.stringify(body) to origin + '/bws/api' + relativePath with these headers.
```

Errors follow BWS conventions. While disabled, all four routes return HTTP 400 with
`{ "code":"PRICE_ALERTS_DISABLED", "message":"Price alerts are disabled" }` before
authentication/storage. Bad credentials return HTTP 401 `NOT_AUTHORIZED`; invalid
fields return HTTP 400; `PRICE_ALERTS_UNREGISTERED` and `PRICE_ALERTS_LIMIT` identify
registration and rule-cap failures. Selector/provider errors include an HTTP error
message. Owner, alert-set, wallet, copayer and Braze IDs cannot override rule ownership.

The three mutations share **300 requests per IP per 10 minutes**, with no response
delay. Counters are in memory per API process. The IP is whatever Express reports;
BWS already enables `trust proxy`, so ingress must set forwarded-address headers
correctly. This is an initial default to observe, not a proven threshold for shared
IPs. `ignoreRateLimiter` retains its existing development/test meaning.

## Assets and rules

Native selectors omit chain/address: `coin=btc`, `coin=pol`, etc. Current resolver
natives are btc, bch, doge, eth, ltc, pol, sol, xrp and arc; arc uses the usd-coin market.
Tokens use `chain=eth&tokenAddress=<contract>`; chains are eth, matic (alias pol), arb,
base, op, arc and sol. Optional token `coin` on PUT must match the provider's symbol.
DELETE ignores token `coin`, validates/normalizes locally, and never calls CoinGecko.
Client-selected provider IDs and client-supplied names are not accepted.

Canonical keys are `native:<coin>` or `token:<normalized-chain>:<validated-address>`.
EVM addresses are lowercase; Solana mint case is preserved. Equal addresses on
different chains remain distinct. Currency, threshold and destination do not enter
identity. Different canonical assets can share one provider observation.

Allowed thresholds are 5, 10, 15 and 20, in either direction. Currencies come from
`Defaults.FIAT_CURRENCIES`: USD, INR, GBP, EUR, CAD, COP, NGN, BRL, ARS, AUD, JPY, NZD.
Lowercase input codes normalize to uppercase. Stablecoins use actual market quotes,
never assumed pegs. The stored name/symbol come from CoinGecko and can differ from
the app's own names. Tokens reuse contract metadata. Native name lookup uses existing
cached market stats **in USD**, including for COP rules; only observations use the
rule's currency. Metadata is captured at creation and retained on subsequent edits.

Saving replaces the configuration of one asset rule without changing cooldowns.
Identical retries do not change `updatedAt`. The default enabled-rule cap is 50 per
set, applied when adding/re-enabling; small concurrent overshoots are accepted. This
is an abuse bound, not the app's 20-asset watchlist limit. BWS has no watchlist.

## Ownership, cooldown and best-effort delivery

`priceAlertSetForOwner` is the only owner-to-set mapping. In v1 each owner has one set
whose ID equals the owner identifier. Rules and cooldowns belong to that set; Braze
is only a destination. Login/logout/account switching never merges or migrates rules.
Independent app keys sharing a destination keep independent rules and cooldowns.

A fresh observation qualifies when `abs(change24hPct) >= thresholdPct`, using the
provider's full precision and its rolling 24-hour percentage **in the selected fiat**.
There is no interpolation, crossing detection, hysteresis, rearming, or requirement
for a changed source timestamp. A newly enabled rule can fire immediately while the
market is already above threshold, and a sustained condition can fire again after
cooldown. +9.8% does not qualify for 10%; +10.2% does. +10.8% and -10.5% inside that
same cooldown do not reserve again.

The atomic boundary is one conditional update of the rule. It checks enabled state,
the read threshold/currency/provider, and eligibility, and sets `nextEligibleAt` to
the worker's reservation clock plus 24 hours. Only an acknowledged update matching
and modifying one rule authorizes a send. Failed/uncertain updates authorize no send
and stop further reservations in that poll. They are not undone.

There is one cooldown per set and asset, shared across directions. Edits, disable/
re-enable, pauses, retries, fiat changes and destination changes never reset it.
Cooldown measures **reservation times**, so delayed actual sends or arrivals may be
closer than 24 hours. Each reservation permits at most one send attempt, with no
delivery guarantee. Rejection, timeout, network failure or a process dying before
send loses that alert for the entire cooldown. There is no retry queue, lease or
recovery pass. Correctness does not require graceful shutdown.

Writes inherit the Mongo connection's write concern, including majority when already
configured; this feature neither overrides nor weakens it. If the configured concern
permits acknowledged reservations to roll back on failover, a repeat alert becomes
possible. This is the exception to reservations being at least 24 hours apart.

Both API and worker read registrations/rules from the primary. Preferences and
destinations read before reservation are honored. A pause, edit or destination change
after the worker's read may not be; nothing recalls an already sent/accepted request.

## Worker, storage and notification contract

The worker has one nonoverlapping loop, waiting `pollIntervalMs` after each completed
poll. It discovers distinct enabled market/currency pairs, polls [CoinGecko `/simple/price`](https://docs.coingecko.com/reference/simple-price) with
all needed currencies, at most 515 IDs per batch (default 100), and at most two
requests in flight. It reuses configured CoinGecko URL and Pro credentials, with a
15-second provider timeout and no in-poll retry or stale-cache fallback.

Each price must be finite and positive, each change finite (zero is valid), and each
source time valid Unix seconds converted to milliseconds. Default maximum age is five
minutes; timestamps over 30 seconds in the future are rejected. Invalid partial
responses and failed batches skip only affected observations. Skip reasons are
aggregated in operational logs per poll.

Eligible rules page by ascending `_id`, 100 at a time, reading registrations per
page. Paused, push-ineligible or missing registrations receive no reservation. The
worker rechecks freshness before every reservation. A scan permits at most 1,000
successful reservations per market/currency per poll; skipped/conflicting candidates
do not count. In-memory cursors continue early-stopped scans and wrap around without
skipping the next unprocessed candidate. There is no persisted backlog. One worker is
normally enough; additional workers coordinate only through atomic reservations and
each independently multiplies provider traffic.

Two collections are added: `price_alert_registrations` (`_id` = owner) and
`price_alert_rules` (`_id` = SHA-256 of JSON `[alertSetId, assetKey]`). Deterministic IDs
enforce uniqueness before background index creation completes. Duplicate upserts
retry as updates for MongoDB 3.6. Queries use indexes on `(alertSetId, enabled)` and
`(enabled, providerId, code, _id, thresholdPct, nextEligibleAt)`. Only classic update
operators are used; no transactions/pipeline updates or TTL deletion. Disabled rules
and registrations remain stored. Tests wait for indexes and clean both collections.

Braze uses the existing `pushNotificationsOpts` URL/key and [Braze `/messages/send`](https://www.braze.com/docs/api/endpoints/messaging/send_messages/post_send_messages), with an
alert-only 10-second timeout. Wallet notification sending is unchanged. Identical
messages group into requests of at most 50 external IDs, with bounded concurrency
(default two). Independent reservations for a repeated destination use separate
requests. Logs classify requests as accepted (including dispatch ID when supplied),
rejected or unknown (network/timeout); none are retried. Subscription defaults are
respected; no override includes unsubscribed recipients. Marketing audience rules
are **not** automatically applied by direct `/messages/send`.

Both platforms receive the exact English copy: title `Price Alert: Bitcoin`, body
`Bitcoin has moved 5%. View the latest price.` Name and configured threshold vary.
Apple and Android `extra` metadata are identical: `notification_type: price_alert`,
`assetKey`, `currencyAbbreviation`, optional `chain`/`tokenAddress`, `name`, `symbol`,
`thresholdPct`, signed full-precision `change24hPct`, `direction` (up/down), quote
`code`, `price`, `observedAt` and `sentAt` (Unix milliseconds), and `observationId`.
The observation ID hashes provider ID, fiat, source time, price and change. `sentAt`
is the request-attempt time, not arrival time. No custom product analytics are exported.

Both platform payloads use `custom_uri`:

```text
bitpay://exchange-rate?currencyAbbreviation=btc&notification_type=price_alert&code=USD
bitpay://exchange-rate?currencyAbbreviation=usdc&chain=eth&tokenAddress=0x...&notification_type=price_alert&code=COP
```

Query values are URL-encoded. **The app must decode them**, and route tokens by chain
and address rather than ticker alone. Existing app routing handles only default
coins and still needs extension for arbitrary tokens. That app work is not included.

## Configuration and operations

`priceAlertsOpts` defaults (also in `bws.example.config.js`):

```js
{
  enabled: false, workerEnabled: false,
  pollIntervalMs: 60000, maxSourceAgeMs: 300000, coinGeckoBatchSize: 100,
  brazeTimeoutMs: 10000, brazeConcurrency: 2, maxEnabledRules: 50,
  campaignId: '', appleMessageVariationId: '', androidMessageVariationId: ''
}
```

Optional reporting identifiers are existing Braze campaign/message variation IDs;
BWS creates no campaigns. Reuse `coinGecko.api`/`apiKey` and
`pushNotificationsOpts.pushServerUrlBraze`/`authorizationKeyBraze`. Do not put secrets
in tracked files. There is no Demo-key support or configurable alert currency list.

| Feature | Worker | API | Worker process |
| --- | --- | --- | --- |
| Off | Either | Disabled error | Alive but idle; no DB/provider work |
| On | Off | Available | Alive but idle |
| On | On | Available | Normal polling/delivery |

Both switches are captured at startup; restart affected processes after changes.
Build using the repository's declared Node/runtime and dependency setup, then run
`npm run compile` in BWS. Start the worker directly with
`node ts_build/src/pricealertsservice/pricealertsservice.js`, or use existing
`start.sh`/`start-docker.sh` (which now include it). `stop.sh` includes its pid.
The disabled daemon stays alive so its pid file remains accurate. Startup scripts'
abrupt termination remains acceptable: no shutdown handler is needed for correctness.

Deployment order:

1. To enable, enable and verify the API on **every serving instance**, then start workers.
2. To disable, stop **every worker**, confirm every worker process has exited, then disable the API.
3. To pause sending while preserving management, stop workers and leave the API enabled.

A notification already accepted by Braze may still arrive. Before production
activation, someone at BitPay who owns the risk must accept the unverified-destination
limitation below.

### Development checks

Run `npm run compile`, `npm run lint`, and `npm test` in BWS. Tests use only `bws_test`
and stub provider/delivery HTTP; they need no production credentials. For focused
tests, after compiling run `../../node_modules/.bin/mocha 'ts_build/test/pricealerts/*.test.js'`.
Use `DB_HOST`/`DB_PORT` to select the test server. If Docker is available, use the
repository's MongoDB 3.6.23 test compose files and `DB_PORT=7357` as in CI. A newer
local server does not prove 3.6 compatibility; inspect for classic updates/no transactions.

For an **optional manual provider-only** development smoke check, keep both switches
off. This script uses locally configured CoinGecko credentials and sends no pushes:

```js
// Run with node from the BWS directory after compiling.
const assert = require('assert');
const { CoinGeckoService } = require('./ts_build/src/externalservices/coingecko');
(async () => {
  const data = await new CoinGeckoService(null).priceAlertPrices(
    ['bitcoin', 'ethereum', 'usd-coin'], ['USD', 'COP']);
  for (const id of ['bitcoin', 'ethereum', 'usd-coin']) {
    const point = data[id];
    assert(Number.isFinite(point?.last_updated_at));
    const age = Date.now() - point.last_updated_at * 1000;
    assert(age >= -30000 && age <= 300000, id + ': source time is not recent');
    for (const code of ['usd', 'cop']) {
      assert(Number.isFinite(point[code]) && point[code] > 0);
      assert(Number.isFinite(point[code + '_24h_change']));
    }
  }
  console.log('BTC, ETH and USDC: numeric USD/COP prices and changes, recent timestamps');
})().catch(err => { console.error(err.message); process.exitCode = 1; });
```

This manual live check is not part of automated tests or a substitute for mocked
freshness/failure tests. Never exercise real Braze sends as a development smoke check.

## Accepted limitations and future app integration

- A replacement identity cannot see/manage a lost identity's rules. If the app loses
  its key, for example on reinstall, old rules stay active. For a signed-in user they
  keep reaching every device on the account; the remaining lever is turning push
  notifications off. There is no orphan cleanup or reinstall recovery.
- Independent identities can generate duplicate-looking notifications; Braze can
  deliver to every device associated with a profile.
- **BWS authenticates the app signing identity but accepts its asserted Braze destination
  without proving control of that destination. A caller who obtains another user's
  valid destination ID could register independently owned alerts targeting it.**
- **App-key authentication does not establish one identity per installation or prevent
  a caller from generating many identities. Request limits and bounded worker
  processing reduce resource exposure but do not eliminate it.**
- Captured signed requests can be replayed indefinitely. Replaying an older
  registration can roll back its destination and preferences. No nonce, timestamp,
  request-age, challenge or session scheme is added.

Future app lifecycle: register/refresh destination and explicit preferences; fetch
configured rules; append any missing returned assets to the persisted local watchlist;
clear an alert before removing its watched asset. Individually disabling an alert
keeps the local asset. When fiat changes, update each configured rule; cooldowns stay.

Deferred: app UI/networking/watchlist and BWC client methods, token deep-link routing,
delivery retries, destination verification, custom analytics/Mixpanel, geography,
Demo keys, BitPay account authentication/merging/sync, new device identity, orphan
cleanup/reinstall recovery, legacy FX parity, historical price storage and Moralis alerts.

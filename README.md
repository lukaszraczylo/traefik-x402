# traefik-x402

A Traefik middleware plugin that charges for HTTP resources with the
[x402 v2](https://github.com/coinbase/x402/blob/main/specs/x402-specification-v2.md)
payment protocol.

You choose the URLs. A client that requests one of them without a valid payment
receives `402 Payment Required` with the price. The client pays and retries. The plugin
verifies and settles the payment through an x402 facilitator, then serves the
response. Unprotected URLs pass through with about 35 ns of overhead and no
allocation.

- Protect exact URLs, prefixes, suffixes, or any mix of them.
- Accept several assets for one URL: USDC, any ERC-20 token that supports
  EIP-3009, SPL tokens, or any other asset your facilitator supports.
- Never charge for an upstream error. Payment settles only after the upstream
  returns a status below 400.
- Stream paid responses without buffering them.
- Written for Traefik's Yaegi interpreter: standard library only, no
  dependencies, no vendor directory.

## How it works

```mermaid
sequenceDiagram
    participant C as Client
    participant T as Traefik + x402 plugin
    participant F as Facilitator
    participant U as Upstream
    C->>T: GET /premium/data
    T-->>C: 402 + PAYMENT-REQUIRED
    C->>T: GET /premium/data + PAYMENT-SIGNATURE
    T->>F: POST /verify
    F-->>T: isValid
    T->>U: GET /premium/data
    U-->>T: 200
    T->>F: POST /settle
    F-->>T: success + transaction
    T-->>C: 200 + PAYMENT-RESPONSE
```

## Quick start

Enable the plugin in the Traefik static configuration:

```yaml
experimental:
  plugins:
    x402:
      moduleName: github.com/lukaszraczylo/traefik-x402
      version: v0.1.0
```

Define the middleware in a dynamic configuration:

```yaml
http:
  middlewares:
    pay:
      plugin:
        x402:
          facilitatorURL: https://x402.org/facilitator
          accepts:
            - network: eip155:84532          # Base Sepolia (CAIP-2)
              amount: "10000"                # atomic units: 0.01 USDC
              asset: "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
              payTo: "0x209693Bc6afc0C5328bA36FaF03C514EF312287C"
              extra: { name: USDC, version: "2" }
          exact:    [/report]
          prefixes: [/premium/]
          suffixes: [.pdf]
  routers:
    api:
      rule: Host(`api.example.com`)
      service: api
      middlewares: [pay]
```

Test it:

```console
$ curl -si https://api.example.com/premium/data | head -3
HTTP/2 402
payment-required: eyJ4NDAyVmVyc2lvbiI6Mi...
$ curl -s https://api.example.com/free
```

Use an [x402 client](https://github.com/coinbase/x402) to sign and send the
`PAYMENT-SIGNATURE` header.

## Choose which URLs to protect

A rule selects a request when its path matches **any** of these lists:

| Field | Matches when the path | Example |
| --- | --- | --- |
| `exact` | equals the entry | `/report` matches `/report` only |
| `prefixes` | starts with the entry | `/premium/` matches `/premium/a/b` |
| `suffixes` | ends with the entry | `.pdf` matches `/docs/manual.pdf` |

Entries in `exact` and `prefixes` must start with `/`. Matching is case-sensitive
unless you set `ignoreCase: true`. The plugin matches the query-free,
percent-decoded path.

The plugin tests the raw path and its cleaned form. The request
`/free/../premium/x` is therefore still protected, even if your backend
resolves `..`. The request `/report/` matches `exact: [/report]` for the same
reason.

The top-level `exact`, `prefixes`, `suffixes` and `methods` fields form one
implicit rule. For several prices or assets, use `rules`. The plugin applies the
first matching rule. The implicit rule comes last.

```yaml
x402:
  facilitatorURL: https://x402.org/facilitator
  accepts: [ ... ]              # default price list
  prefixes: [/api/]             # implicit rule, default price
  rules:
    - name: expensive-report
      exact: [/api/report]
      description: Quarterly report
      mimeType: application/pdf
      methods: [GET]            # default: every method except OPTIONS
      accepts:                  # replaces the default list for this rule
        - network: eip155:8453
          amount: "5000000"
          asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
          payTo: "0x209693Bc6afc0C5328bA36FaF03C514EF312287C"
          extra: { name: USD Coin, version: "2" }
```

CORS preflight requests (`OPTIONS`) are never charged unless a rule lists
`OPTIONS` in `methods`.

## Accept several assets for one URL

Each entry of `accepts` is one payment option. List as many as you want. The
client picks one and echoes it in `PAYMENT-SIGNATURE`. The plugin accepts the
payment only if the echoed option equals one of yours exactly.

```yaml
accepts:
  - network: eip155:8453
    amount: "10000"                       # 0.01 USDC (6 decimals)
    asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
    payTo: "0x209693Bc6afc0C5328bA36FaF03C514EF312287C"
    extra: { name: USD Coin, version: "2" }
  - network: eip155:8453
    amount: "10000000000000000"           # 0.01 DAI (18 decimals)
    asset: "0x50c5725949A6F0c72E6C4a641F24049A917DB0Cb"
    payTo: "0x209693Bc6afc0C5328bA36FaF03C514EF312287C"
    extra: { name: Dai Stablecoin, version: "1" }
  - network: solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp
    amount: "10000"
    asset: EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v
    payTo: "<solana address>"
```

Rules for the fields:

- `amount` is a decimal string in the token's atomic units. Compute it from the
  token decimals. Different tokens need different amounts.
- `asset` is the token contract address (EVM), the mint (Solana) or an ISO 4217
  code.
- `extra` carries scheme data. For EIP-3009 tokens set the EIP-712 domain
  `name` and `version` of the token contract. The values differ per token.
- `network` is a [CAIP-2](https://chainagnostic.org/CAIPs/caip-2) identifier.
- `scheme` defaults to `exact`. `maxTimeoutSeconds` defaults to `60`.

Your facilitator must support every asset and network you list. The plugin does
not check this at start-up.

## Facilitator

| Field | Default | Purpose |
| --- | --- | --- |
| `facilitatorURL` | required | Base URL. The plugin calls `/verify` and `/settle`. |
| `facilitatorTimeout` | `10s` | Timeout for each facilitator call. |
| `facilitatorHeaders` | none | Static headers, for example an API key. |
| `allowInsecureFacilitator` | `false` | Permits an `http://` URL. Use it for tests only. |

The plugin keeps a pool of up to 128 idle connections to the facilitator.
Facilitators that need a per-request signed token (a short-lived JWT) cannot
use `facilitatorHeaders`. Put an authenticating proxy in front of them.

The plugin forwards the client payload to the facilitator byte for byte, so
fields that it does not know still reach the facilitator. The
`paymentRequirements` field always holds your configured option, never the
client copy.

## Settlement timing

| `settlement` | Order | Upstream error | Best for |
| --- | --- | --- | --- |
| `after` (default) | verify, upstream, settle | not charged | normal APIs |
| `before` | verify, settle, upstream | charged | streaming, upgrades |

In `after` mode, settlement runs when the upstream commits to a status below
400, before the first byte reaches the client. The body then streams without
buffering. If settlement fails, the plugin discards the upstream response and
sends `402` with a `PAYMENT-RESPONSE` header that describes the failure.

Set `settlement` per rule or globally. A rule value wins.

> **Streaming and WebSocket.** Traefik runs plugins in Yaegi. Yaegi hides the
> `Flusher` and `Hijacker` interfaces of a wrapped response writer, so the
> `after` mode would delay server-sent events and break connection upgrades.
> The plugin therefore settles **before** the upstream for any request that
> has an `Upgrade` header or `Accept: text/event-stream`. The end-to-end test
> shows this on a real Traefik.

## Replay protection

Between verification and settlement, one signed authorization could unlock many
concurrent requests. The blockchain stops a double spend, but you would give the
extra requests away for free. The replay guard prevents this. It rejects a
second request that carries a payment already in use with `402` and the reason
`payment_already_used`.

- It is on by default. Set `replayGuard: false` to disable it.
- A payment that was never settled (upstream error, failed settlement) is
  released, so the client can retry.
- The state is in memory and per Traefik instance. With several replicas, the
  chain and the facilitator are the shared guard.
- Each shard holds at most 8192 entries. A full shard lets requests through
  rather than blocking paying clients.

## Other options

| Field | Default | Purpose |
| --- | --- | --- |
| `payerHeader` | none | Sets this header on the upstream request to the payer address. The plugin removes any client-supplied value on every request. |
| `forwardPaymentHeader` | `false` | Forwards `PAYMENT-SIGNATURE` to the upstream. By default the plugin removes it. |
| `resourceBaseURL` | derived | Fixes the scheme and host in `resource.url`. Otherwise the plugin uses `X-Forwarded-Proto`, `X-Forwarded-Host` and the `Host` header. |
| `extensionsJSON` | none | A JSON object that the plugin adds as `extensions` to each `PaymentRequired`, for example the Bazaar discovery extension. |
| `ignoreCase` | `false` | Case-insensitive path matching. |
| `description`, `mimeType` | none | Set `resource.description` and `resource.mimeType` for the implicit rule. A rule has its own fields. |

Set `resourceBaseURL` unless Traefik overwrites `X-Forwarded-*` headers from
untrusted clients. A client can otherwise influence the `resource.url` that it
receives back. The plugin does not use that value for any decision.

## x402 v2 compliance

The behaviour below follows the core specification and the HTTP transport
specification at `coinbase/x402` (`specs/x402-specification-v2.md` and
`specs/transports-v2/http.md`).

| Requirement | Behaviour |
| --- | --- |
| `PaymentRequired` | `x402Version: 2`, `error`, `resource`, `accepts`, optional `extensions`. Sent base64-encoded in `PAYMENT-REQUIRED` and as the JSON body. |
| Unpaid request | `402` with the message `PAYMENT-SIGNATURE header is required`. |
| `PaymentPayload` | Read from `PAYMENT-SIGNATURE` as base64 JSON. Standard and URL-safe alphabets work, with or without padding. |
| Requirement matching | The `accepted` object must equal one configured option, including `extra`. |
| Malformed payment | `400` for bad base64, bad JSON, a missing `accepted` field, or `x402Version` other than `2`. |
| Verification | `POST {facilitator}/verify` with `x402Version`, `paymentPayload`, `paymentRequirements`. |
| Invalid payment | `402` with the facilitator `invalidReason` as `error`. |
| Settlement | `POST {facilitator}/settle` with the same body. |
| `SettlementResponse` | Relayed unchanged in `PAYMENT-RESPONSE`, on success and on failure. |
| Settlement failure | `402` with `PAYMENT-RESPONSE` and `PAYMENT-REQUIRED`. |
| Facilitator unreachable or invalid | `500` with `unexpected_verify_error` or `unexpected_settle_error`. |
| Networks | CAIP-2 identifiers, validated at start-up. |
| Extensions | Advertised through `extensionsJSON`. The client echo goes to the facilitator untouched. |

Not part of this plugin: the facilitator service, the `/supported` endpoint,
discovery (`/discovery/resources`) and client-side signing. The plugin does not
convert prices. You write the `amount` in atomic units.

## Performance

Measured with `make bench` on an darwin/arm64 laptop (Go 1.27.1, compiled,
not interpreted):

| Case | Time | Allocations |
| --- | --- | --- |
| Request outside every rule | 35 ns | 0 |
| Rule lookup (3 prefixes, 2 suffixes, 4 exact) | 24 ns | 0 |
| Build a `402` response (2 assets) | 860 ns | 15 |
| Decode a payment header | 1.6 µs | 11 |
| Replay guard claim and release | 52 ns | 0 |

Design choices behind these numbers:

- Rules compile once. Exact paths use a map. Prefix and suffix scans use no
  allocation.
- Each requirement is encoded to JSON at start-up. A `402` only concatenates
  bytes.
- The plugin sends the payload to the facilitator without re-encoding it.
- Paid responses stream. The plugin never buffers the body.
- The facilitator call dominates paid-request latency. The pooled client reuses
  connections to keep it to one round trip for each of verify and settle.

Under Yaegi the interpreted code runs slower than these compiled figures. The
facilitator network round trip is still the larger cost.

## Security notes

- The plugin removes `PAYMENT-SIGNATURE` before it forwards the request, so the
  upstream cannot reuse a pending authorization.
- Use an `https://` facilitator URL. The plugin rejects `http://` unless you set
  `allowInsecureFacilitator`.
- The plugin never logs payment payloads.
- The plugin matches paths after decoding and cleaning, which closes the
  `..` and `//` bypasses.
- Trust the `payTo` value only from your configuration. The plugin never takes
  it from the client.

## Development

```console
make test         # unit tests with the race detector
make cover        # coverage summary
make lint         # gofmt, vet, golangci-lint, fieldalignment, gosec, govulncheck
make bench        # benchmarks
make yaegi-check  # load the plugin in Yaegi like the Plugin Catalog does
make e2e          # run the plugin in a real Traefik container (needs docker)
```

- Unit tests cover 98% of statements.
- `tools/yaegi-check` loads the plugin in Yaegi v0.16.1, decodes the
  `.traefik.yml` test data, calls `New` across the reflect boundary and drives
  payment flows through the interpreted handler.
- `integration` starts `traefik:v3.7` with the plugin as a local plugin. It uses a
  mock facilitator and a mock upstream on the host. The tests cover the full
  flow: `402`, exact/prefix/suffix rules, two assets, replay rejection, upstream
  errors, failed settlement and streaming.

The plugin follows the Yaegi rules from the Traefik catalog: no generics from
the standard library, no `atomic.Pointer`, and no tail-call returns in `New`.

## Licence

MIT.

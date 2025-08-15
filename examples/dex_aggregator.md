# DEX Aggregator API

The Intear DEX Aggregator provides optimal trading routes across multiple decentralized exchanges on the NEAR blockchain, ensuring users get the best prices with minimal slippage.

The main API endpoint is available at: `https://router.intear.tech/route`

This service is currently not supported on testnet.

## Supported DEXs

The aggregator currently integrates with the following decentralized exchanges:

- **Rhea** - AMM DEX at [dex.rhea.finance](https://dex.rhea.finance/)
- **NearIntents** - Guaranteed-quote DEX & Bridge at [app.near-intents.org](https://app.near-intents.org/)
- **Veax** - AMM DEX at [app.veax.com](https://app.veax.com/)
- **Aidols** - Bonding-curve launchpad at [aidols.bot](https://aidols.bot/)
- **GraFun** - Bonding-curve launchpad at [gra.fun](https://gra.fun/)
- **Jumpdefi** - AMM DEX at [app.jumpdefi.xyz](https://app.jumpdefi.xyz/swap) *(Not implemented yet)*

## Getting Routes

### Route Request

Get the best route for a token swap:

```
GET https://router.intear.tech/route?token_in=17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1&token_out=near&amount_out=2000000000000000000000000&max_wait_ms=1500&slippage_type=Auto&max_slippage=0.1&min_slippage=0.001&dexes=Rhea%2CVeax%2CAidols%2CGraFun%2CJumpdefi%2CWrap%2CRheaDcl&trader_account_id=test.slimegirl.near&signing_public_key=ed25519%3A6asoE6aiJe2ebkgFpmsTmbTWcZFXamnBMu5vzRi8cRvQ
```

**Parameters:**

- `token_in` - Token to swap from (`near` for NEAR, or contract ID for NEP-141 tokens)
- `token_out` - Token to swap to (`near` for NEAR, or contract ID for NEP-141 tokens)
- `amount_in` OR `amount_out` - Amount to swap (in token's smallest unit)
- `max_wait_ms` - Maximum wait time in milliseconds (up to 60000ms). Some DEXes like Near Intents can benefit from a longer wait time to get a better quote
- `slippage_type` - Either `Auto` or `Fixed`
  - For `Auto`: also provide `max_slippage` and `min_slippage`
  - For `Fixed`: also provide `slippage`
- `slippage` / `max_slippage` / `min_slippage` - Slippage as decimal (e.g., 0.01 = 1%)
- `dexes` (optional) - Comma-separated list of DEX IDs to use. If empty, all available exchanges will be used
- `trader_account_id` (optional) - Account ID for storage deposit actions
- `signing_public_key` (optional) - Public key for NEAR Intents signing (it requires `add_public_key` transaction)

**Token ID Format:**
- NEAR: `near`
- NEP-141 tokens: Contract account ID (e.g., `usdt.tether-token.near`)

### Route Response

The API returns a `Route` object with the following structure:

```json
[
  {
    "deadline": null,
    "has_slippage": true,
    "estimated_amount": {
      "amount_out": "2445573"
    },
    "worst_case_amount": {
      "amount_out": "2431021"
    },
    "dex_id": "Rhea",
    "execution_instructions": [
      {
        "NearTransaction": {
          "receiver_id": "wrap.near",
          "actions": [
            {
              "FunctionCall": {
                "method_name": "near_deposit",
                "args": "e30=",
                "gas": 2000000000000,
                "deposit": "1000000000000000000000000"
              }
            },
            {
              "FunctionCall": {
                "method_name": "ft_transfer_call",
                "args": "eyJhbW91bnQiOiIxMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwIiwibXNnIjoie1wiYWN0aW9uc1wiOlt7XCJhbW91bnRfaW5cIjpcIjEwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDBcIixcImFtb3VudF9vdXRcIjpcIjBcIixcIm1pbl9hbW91bnRfb3V0XCI6XCIwXCIsXCJwb29sX2lkXCI6Mzg3OSxcInRva2VuX2luXCI6XCJ3cmFwLm5lYXJcIixcInRva2VuX291dFwiOlwidXNkdC50ZXRoZXItdG9rZW4ubmVhclwifSx7XCJhbW91bnRfb3V0XCI6XCIwXCIsXCJtaW5fYW1vdW50X291dFwiOlwiMjQzMTAyMVwiLFwicG9vbF9pZFwiOjQ1MTMsXCJ0b2tlbl9pblwiOlwidXNkdC50ZXRoZXItdG9rZW4ubmVhclwiLFwidG9rZW5fb3V0XCI6XCIxNzIwODYyOGY4NGY1ZDZhZDMzZjBkYTNiYmJlYjI3ZmZjYjM5OGVhYzUwMWEzMWJkNmFkMjAxMWUzNjEzM2ExXCJ9XSxcImZvcmNlXCI6MCxcInNraXBfZGVnZW5fcHJpY2Vfc3luY1wiOnRydWUsXCJza2lwX3Vud3JhcF9uZWFyXCI6dHJ1ZX0iLCJyZWNlaXZlcl9pZCI6InYyLnJlZi1maW5hbmNlLm5lYXIifQ==",
                "gas": 90000000000000,
                "deposit": "1"
              }
            }
          ],
          "continue_if_failed": false
        }
      }
    ],
    "needs_unwrap": false
  }
]
```

**Response Fields:**

- `deadline` - Route expiration time (refresh 2-3 seconds before)
- `has_slippage` - Whether the route includes slippage (AMM vs guaranteed quote)
- `estimated_amount` - Expected swap amount
- `worst_case_amount` - Minimum guaranteed amount with slippage
- `dex_id` - Which DEX provided this route
- `execution_instructions` - Array of instructions to execute the swap
- `needs_unwrap` - Whether manual unwrapping is needed after the swap

## Execution Instructions

Routes contain execution instructions that must be processed sequentially:

### NEAR Transaction

```json
{
  "NearTransaction": {
    "receiver_id": "v2.ref-finance.near",
    "actions": [
      {
        "FunctionCall": {
          "method_name": "ft_transfer_call",
          "args": "base64-encoded-args",
          "gas": "30000000000000",
          "deposit": "1"
        }
      }
    ],
    "continue_if_failed": false
  }
}
```

Execute this as a standard NEAR transaction with the specified receiver and actions.

### NEAR Intents Quote (Advanced)

```json
{
  "IntentsQuote": {
    "message_to_sign": "{...}",
    "quote_hash": "quote-hash"
  }
}
```

For NEAR Intents, sign the NEP-413 message and send it to:
```
POST https://solver-relay-v2.chaindefuser.com/rpc
```

See [NEAR Intents documentation](https://docs.near-intents.org/near-intents/market-makers/bus/solver-relay) for more details and examples.

## Amount Types

The API supports two swap modes:

### Amount In (Most Common)
Specify the input amount, get the estimated output:
```
amount_in=1000000000000000000000000
```

### Amount Out
Specify the desired output amount, get the required input:
```
amount_out=4250000
```

*Note: Not all DEXes support AmountOut mode*

## Slippage Configuration

### Auto Slippage
```
slippage_type=Auto&max_slippage=0.05&min_slippage=0.001
```
Automatically determines optimal slippage based on market conditions.

### Fixed Slippage
```
slippage_type=Fixed&slippage=0.01
```
Uses a fixed slippage percentage (1% in this example).

## DEX Capabilities

| DEX | Amount In | Amount Out | Special Notes |
|-----|-----------|------------|---------------|
| Rhea | ✅ | ❌ | AMM with slippage |
| RheaDcl | ✅ | ✅ | AMM with slippage |
| NearIntents | ✅ | ✅ | Guaranteed quotes, no slippage |
| Veax | ✅ | ✅ | AMM with slippage |
| Aidols | ✅ | ✅ | Only `*.aidols.near` tokens |
| GraFun | ✅ | ❌ | Only `*.gra-fun.near` tokens |
| Jumpdefi | ❌ | ❌ | *Not implemented yet* |
| Wrap | ✅ | ✅ | NEAR ↔ wNEAR only |
| MetaPool | ✅ | ✅ | NEAR ↔ STNEAR only |
| Linear | ✅ | ✅ | NEAR ↔ LiNEAR only |

## What is handled and what is not

If you choose `near` as input / output asset, wrapping / unwrapping will be handled by the API, all wrap / unwrap / storage_deposit / add_public_key (for Intents) / other required methods will be included in the response, as long as the necessary data is there (make sure to include optional fields such as `trader_account_id` to have these calls included in the response).

If the response has `needs_unwrap: true`, it's your job as an API user to track the amount of wNEAR (view `ft_balance_of` on `wrap.near` with args `{"account_id": "user.near"}`) before and after the swap, and manually create an unwrap transaction (execute `near_withdraw` on `wrap.near` with args `{"amount": "1000000000000000000000 (this number is the difference the balance before and after swap)"}`). This might be necessary because in ExactIn mode you don't know how much wNEAR you're going to get, and in ExactOut mode you're sending a bit more wNEAR and don't know how much can be refunded. In cases the service can know for sure how much wNEAR you're going to get (for example, Near Intents transactions don't have slippage, or AIdols ExactOut mode where you sell a token, or when you're trading non-NEAR pairs, or when you specified `wrap.near` instead of `near`), the service will include the unwrap operation as needed, and set `needs_unwrap` to false.

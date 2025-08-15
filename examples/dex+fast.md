# Using DEX Aggregator with FastINTEAR

This guide provides sample code for integrating the Intear DEX Aggregator API with the FastINTEAR JavaScript SDK. The aggregator helps find optimal trading routes across multiple DEXs on NEAR, and FastINTEAR handles the blockchain interactions.

## Prerequisites

- Install FastINTEAR: `npm install fastintear`
- Configure network: `near.config({ networkId: "mainnet" });`
- Sign in: `await near.requestSignIn();`

## Basic Swap Example

Fetch a route and execute the swap.

```javascript
async function performSwap(tokenIn, tokenOut, amountIn) {
  const params = new URLSearchParams({
    token_in: tokenIn,
    token_out: tokenOut,
    amount_in: amountIn,
    max_wait_ms: '1500',
    slippage_type: 'Auto',
    max_slippage: '0.1',
    min_slippage: '0.001',
    trader_account_id: near.accountId(),
    signing_public_key: near.publicKey()
  });

  const response = await fetch(`https://router.intear.tech/route?${params}`);
  const routes = await response.json();

  if (routes.length === 0) {
    throw new Error('No routes found');
  }

  const bestRoute = routes[0];
  const instructions = bestRoute.execution_instructions;

  for (const instr of instructions) {
    if ('NearTransaction' in instr) {
      const tx = instr.NearTransaction;
      await near.sendTx({
        receiverId: tx.receiver_id,
        actions: tx.actions.map(action => {
          if ('FunctionCall' in action) {
            return near.actions.functionCall({
              methodName: action.FunctionCall.method_name,
              args: JSON.parse(atob(action.FunctionCall.args)),
              gas: action.FunctionCall.gas,
              deposit: action.FunctionCall.deposit
            });
          }
          // Handle other action types as needed
        })
      });
    }
    // Handle other instruction types like IntentsQuote if needed
  }

  if (bestRoute.needs_unwrap) {
    // Manually unwrap wNEAR
    // Implement balance check and near_withdraw call
  }

  return bestRoute;
}

// Usage
performSwap('near', 'usdt.tether-token.near', '1000000000000000000000000')
  .then(console.log)
  .catch(console.error);
```

## Amount Out Mode

Specify desired output amount.

```javascript
// Similar to above, but use amount_out instead of amount_in
```

## Handling Slippage

Use Auto slippage for optimal rates.

For more details, see [DEX Aggregator Documentation](/dex_aggregator.md) and [FastINTEAR Context](/fastintear-llm-context.md).

Save this as `dex_aggregator_samples.md` in your workspace.


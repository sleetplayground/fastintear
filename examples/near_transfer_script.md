# NEAR Console Transfer Script

This script tests the transaction flow by sending a minimal transfer amount.

**Prerequisite:** You must have the `near` object available globally in your console.

## Instructions

1.  Open the developer console in your web browser.
2.  Copy the entire code block below.
3.  Paste it into the console and press Enter.

```javascript
async function sendNearTransfer() {
  try {
    // 1. Configure for the testnet
    near.config({ networkId: 'testnet' });

    // 2. Sign in via a wallet popup
    await near.requestSignIn(); // No specific contract needed for a transfer
    const accountId = near.accountId();
    
    if (!accountId) {
      console.log('Wallet connection was canceled.');
      return;
    }
    
    console.log(`Connected with account: ${accountId}`);

    // 3. Send a transaction to transfer 1 yoctoNEAR to yourself
    console.log('Sending transaction to transfer 1 yoctoNEAR...');
    const result = await near.sendTx({
      receiverId: accountId, // Sending to yourself is a valid test
      actions: [
        near.actions.transfer('1'), // The amount is in yoctoNEAR
      ],
    });

    console.log('Transaction sent successfully!', result);

  } catch (error) {
    console.error('An error occurred:', error);
  }
}

// Call the function to execute the code
sendNearTransfer();
```


---

copyright 2025 by sleet.near
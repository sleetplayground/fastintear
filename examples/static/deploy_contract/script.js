// Configure FastINTEAR for the testnet
near.config({ networkId: "testnet" });

const loginBtn = document.getElementById('loginBtn');
const logoutBtn = document.getElementById('logoutBtn');
const deployBtn = document.getElementById('deployBtn');
const contractUint8ArrayInput = document.getElementById('contractUint8Array');
const statusSpan = document.getElementById('status');
const accountIdSpan = document.getElementById('accountId');
const deploySection = document.getElementById('deploySection');

// Function to update UI based on authentication status
const updateUI = () => {
    const isSignedIn = near.authStatus() === 'SignedIn';
    statusSpan.textContent = isSignedIn ? 'Signed In' : 'Signed Out';
    accountIdSpan.textContent = isSignedIn ? near.accountId() : 'None';

    loginBtn.style.display = isSignedIn ? 'none' : 'block';
    logoutBtn.style.display = isSignedIn ? 'block' : 'none';
    deploySection.style.display = isSignedIn ? 'block' : 'none';
};

const validateBtn = document.getElementById('validateBtn');
const validationStatusSpan = document.getElementById('validationStatus');

// Event Listeners
validateBtn.addEventListener('click', () => {
    const codeString = contractUint8ArrayInput.value;
    if (!codeString) {
        validationStatusSpan.textContent = 'Cannot validate an empty string.';
        validationStatusSpan.style.color = 'orange';
        return;
    }
    try {
        const bytes = new Uint8Array(codeString.split(',').map(s => parseInt(s.trim())));
        if (bytes.some(isNaN)) {
            throw new Error('String contains non-numeric values.');
        }
        validationStatusSpan.textContent = 'Validation Successful: String is a valid Uint8Array representation.';
        validationStatusSpan.style.color = 'green';
    } catch (e) {
        validationStatusSpan.textContent = 'Validation Failed: This is not a valid Uint8Array string. ' + e.message;
        validationStatusSpan.style.color = 'red';
    }
});

loginBtn.addEventListener('click', async () => {
    await near.requestSignIn({ contractId: near.accountId() });
    updateUI();
});

logoutBtn.addEventListener('click', () => {
    near.signOut();
    updateUI();
});

deployBtn.addEventListener('click', async () => {
    const codeString = contractUint8ArrayInput.value;
    if (!codeString) {
        alert('Please paste the Uint8Array string for the contract.');
        return;
    }

    if (near.authStatus() !== 'SignedIn') {
        alert('You must be logged in to deploy a contract.');
        return;
    }

    try {
        const codeBytes = new Uint8Array(codeString.split(',').map(s => parseInt(s.trim())));
        if (codeBytes.some(isNaN)) {
            alert('Invalid Uint8Array string. Contains non-numeric values.');
            return;
        }

        console.log('Deploying contract for account:', near.accountId());
        const result = await near.sendTx({
            receiverId: near.accountId(),
            actions: [
                {
                    type: "DeployContract",
                    params: {
                        code: Array.from(codeBytes) // Using Array.from() to fix deserialization issue
                    }
                }
            ]
        });
        console.log('Transaction Result:', result);
        alert('Contract deployment transaction sent successfully!');
    } catch (error) {
        console.error('Failed to deploy contract:', error);
        alert('Error deploying contract: ' + error.message);
    }
});

// Initial UI update on page load
window.onload = () => {
    updateUI();
};
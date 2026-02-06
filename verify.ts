import { ethers } from 'ethers';

// 1. YOUR OFFICIAL PUBLIC IDENTITY
const ORACLE_PUBLIC_ADDRESS = "0x0169F5D088b33EF88Dc4F475310dBdd28578E758"; 

async function verifyReceipt(receiptJson: any) {
    console.log("\n🔍 Verifying Headless Oracle Receipt...\n");

    const { data, signature } = receiptJson;

    if (!data || !signature) {
        console.error("❌ Invalid Receipt: Missing data or signature.");
        return;
    }

    // Reconstruct the payload exactly as it was signed
    const payloadString = JSON.stringify(data);

    try {
        // Recover the address that signed this message
        const recoveredAddress = ethers.verifyMessage(payloadString, signature);

        console.log(`   Expected Signer: ${ORACLE_PUBLIC_ADDRESS}`);
        console.log(`   Actual Signer:   ${recoveredAddress}`);

        // Compare (case-insensitive)
        if (recoveredAddress.toLowerCase() === ORACLE_PUBLIC_ADDRESS.toLowerCase()) {
            console.log("\n✅ VERIFIED: This receipt is authentic.");
            console.log("   The data has not been tampered with.");
        } else {
            console.log("\n❌ FAILED: Signature mismatch!");
            console.log("   This receipt was NOT signed by the official Oracle.");
        }

    } catch (error: any) {
        console.error("❌ Error during verification:", error.message);
    }
}

// 2. YOUR LIVE PRODUCTION DATA
const sampleReceipt = {
    "data": {
        "audit_id": "6e015b96-a7a3-4789-b4cd-9bf460baebbc",
        "timestamp_utc": "2026-02-06T11:02:39.773Z",
        "market": "LSE",
        "status": "OPEN",
        "local_time": "11:02:39",
        "message": "The LSE is currently OPEN"
    },
    "signature": "0xd40bc1172e0b8cb6486fd770a54dd2d87384afa58b969960e28a6234dbdc39851445e9ed8c4dbe56c302d250f8dfe48f1c1d97b06e3ef256eb74cbb1708ce1d71b",
    "oracle_v": "3.0-gold"
};

// 3. EXECUTE
verifyReceipt(sampleReceipt);
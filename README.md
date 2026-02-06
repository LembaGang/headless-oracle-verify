# Headless Oracle: Receipt Verifier

**Independent cryptographic verification for Headless Oracle market status receipts.**

---

## 🛑 The Problem
When an autonomous agent (DeFi bot, MEV searcher) makes a decision based on an API, there is usually a **"Trust Gap."** If the API provider changes their logs or lies about a past response, the bot owner has no recourse.

## ✅ The Solution
**Headless Oracle** bridges this gap using **ECDSA signatures**. Every API response is signed by our private key before it leaves the edge. This verification tool allows you to mathematically prove that a receipt is authentic, untampered, and was officially issued by our Oracle.

---

## 🛠 Usage

### 1. Prerequisites
You need **Node.js** installed on your machine.

### 2. Setup
Clone this repository and install the dependencies:
```bash
git clone [https://github.com/YOUR_USERNAME/headless-oracle-verify](https://github.com/YOUR_USERNAME/headless-oracle-verify)
cd headless-oracle-verify
npm install
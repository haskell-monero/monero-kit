---
updated: 2018-11-17
---

monero-kit
====

[Monero][mp] is a cryptoasset focused on fungibility.  It maintains state using 
a proof-of-work blockchain secured by CryptoNightV7 mining.  Unlike most other 
projects, the Monero blockchain is _opaque_ and transactions encrypt the 
recipient and amounts; and obfuscate the spent output.  This requires 
cryptography that combines ring signatures, Confidential Transactions, and 
efficient range proofs (Bulletproofs).

The library includes:

- [ ] Implementations of ring signatures and bulletproofs
- [ ] Data structures: network protocol, addresses, blocks, and transactions
- [ ] Transaction composition API
- [ ] Transaction signing under a signature oracle
- [ ] Transaction (de)serialization to wire format
- [ ] Owned output detection

[mp]: https://getmonero.org

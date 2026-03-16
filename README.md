# @aethyrai/ssi-verify

Lightweight SSI credential and signature verification.

Verification-only library for checking Aethyr SSI credentials and action signatures. No issuance, no key management, no custody. Designed to be embedded in any runtime — MCP servers, PicoClaw agents, AIOS nodes, or any service that needs to verify Aethyr credentials.

## Cryptographic Primitives

| Operation | Algorithm | Standard |
|-----------|-----------|----------|
| Digital signatures | ML-DSA-65 (Dilithium) | NIST FIPS 204 |
| Hashing | BLAKE3 | — |

All post-quantum. Implemented via `@noble/post-quantum` and `@noble/hashes` — zero dependencies, audited, pure TypeScript.

## API

### `verifyCredential(credential, issuerPublicKey)`

Verify a Verifiable Credential's ML-DSA-65 signature and expiry. Does not check revocation.

### `verifyAction(signedAction, signingPublicKey)`

Verify a signed action against a public key.

### `verify(publicKey, data, signature)`

Raw ML-DSA-65 signature verification.

### `matchCapability(granted, requested)` / `matchCapabilities(granted[], requested)`

Glob-style capability matching for authorization checks.

### `parseDID(did)`

Parse a `did:aethyr:<namespace>:<identifier>` DID string.

## Related

- [`@aethyrai/ssi`](https://github.com/aethyrai/ssi) — Full SSI protocol: identity, credentials, signing, key hierarchy

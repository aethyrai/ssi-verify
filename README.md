# @aethyrai/ssi-verify

Verify AI agent identity. Lightweight, embeddable, post-quantum.

## Why This Exists

Autonomous agents are about to walk the streets. They'll book hotel rooms, sign contracts, access medical records, make purchases, and interact with systems on behalf of real people and companies. Every system they touch needs to answer the same question: **who is this agent, who sent it, and what is it allowed to do?**

Today there's no answer. 93% of agent deployments use shared API keys. 68% of organizations can't tell agent actions apart from human activity. No major agent framework provides per-agent cryptographic identity. When an agent misbehaves, there's no way to trace it back to a responsible party without taking everyone else down with it.

That's not a technical inconvenience. It's a blocker for agents operating in the real world. Without verifiable identity, autonomous agents can't be trusted, regulated, or insured.

## What This Library Does

This is the verification side. When an agent presents a credential to your service, `ssi-verify` checks three things:

1. **Is the credential authentic?** — cryptographic signature verification (ML-DSA-65, post-quantum)
2. **Is it still valid?** — expiry checking
3. **Is the agent authorized?** — capability matching against what the credential grants

No network calls. No Aethyr account needed. No API keys. Just math running locally in your service. Install from npm and verify.

The credential itself is issued by Aethyr — the trust authority. Think of Aethyr as the DMV for AI agents. The agent gets a license. Your service checks the license. This library is the scanner at the door.

## Install

```bash
npm install @aethyrai/ssi-verify
```

## Usage

```typescript
import {
  verifyCredential,
  verifyAction,
  verify,
  matchCapability,
  parseDID,
} from '@aethyrai/ssi-verify';

// An agent presents a credential to your service.
// Verify it against Aethyr's public key.
const result = verifyCredential(credential, issuerPublicKey);
if (!result.valid) {
  console.error('Credential invalid:', result.reason);
}

// Check what the agent is allowed to do
matchCapability('tool:hubspot_*', 'tool:hubspot_create_contact'); // true
matchCapability('tool:hubspot_*', 'tool:jobtread_list');          // false

// Verify a signed action
const actionResult = verifyAction(signedAction, signerPublicKey);

// Raw ML-DSA-65 signature verification
const valid = verify(publicKey, data, signature);

// Parse an agent's DID
const parsed = parseDID('did:aethyr:agent:abc123');
// { namespace: 'agent', identifier: 'abc123' }
```

## How It Works

```
┌──────────┐         ┌──────────┐         ┌──────────────┐
│  Agent   │──reg──▶ │  Aethyr  │         │ Your Service │
│          │◀─cred── │ (issuer) │         │  (verifier)  │
└──────────┘         └──────────┘         └──────────────┘
      │                                          ▲
      │          presents credential             │
      └──────────────────────────────────────────┘
                                                  │
                                          ssi-verify checks:
                                          ✓ authentic?
                                          ✓ still valid?
                                          ✓ authorized?
```

1. **Agent registers** with Aethyr and receives a signed credential
2. **Agent presents** the credential when it interacts with your service
3. **Your service verifies** using `ssi-verify` — no network call, fully offline
4. **Your service decides** what the agent can do based on its capabilities

Every credential traces back to a responsible party. If the agent causes harm, you know who deployed it, what it was authorized to do, and who to contact. That's what makes autonomous agents legal, trustworthy, and insurable.

## Why Post-Quantum

Every other agent identity solution uses classical cryptography (Ed25519, RSA, secp256k1). Aethyr uses **ML-DSA-65** (NIST FIPS 204) — a post-quantum signature algorithm. Agent credentials issued today may still be in circulation when quantum computers can break classical signatures. We're not waiting for that to become a problem.

## Cryptography

| Operation | Algorithm | Standard |
|-----------|-----------|----------|
| Digital signatures | ML-DSA-65 (Dilithium) | NIST FIPS 204 |

Implemented via [`@noble/post-quantum`](https://github.com/paulmillr/noble-post-quantum) — zero-dependency, audited, pure TypeScript. Runs in any JavaScript runtime (Node.js, Deno, Bun, browsers).

## API

### `verifyCredential(credential, issuerPublicKey)`

Verify a credential's ML-DSA-65 signature and expiry. Does not check revocation.

### `verifyAction(signedAction, signingPublicKey)`

Verify a signed action against a public key.

### `verify(publicKey, data, signature)`

Raw ML-DSA-65 signature verification.

### `matchCapability(granted, requested)` / `matchCapabilities(granted[], requested)`

Capability matching for authorization. Supports exact matches, trailing wildcards (`tool:hubspot_*`), and universal wildcards (`*`).

### `parseDID(did)`

Parse a `did:aethyr:<namespace>:<identifier>` DID string.

## Standards Alignment

- **W3C Verifiable Credentials 2.0** — credential format
- **W3C Decentralized Identifiers (DIDs)** — agent identity
- **NIST FIPS 204 (ML-DSA)** — post-quantum signatures

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

## License

[MIT](LICENSE)

## Related

- [Aethyr Research](https://aethyrresearch.com) — Trust infrastructure for AI agents
- [Agent Registry](https://registry.aethyr.cloud) — Register your agent and get a credential

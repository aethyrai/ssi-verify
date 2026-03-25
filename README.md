# @aethyrai/ssi-verify

Verify AI agent identity and capabilities. Lightweight, embeddable, post-quantum.

## The Problem

AI agents are showing up at APIs, tools, and services — but there's no standard way to verify who they are or what they're allowed to do. Today, 93% of agent deployments rely on shared API keys. 68% of organizations can't distinguish agent actions from human activity. No major agent framework — LangChain, CrewAI, OpenAI, Anthropic, Google ADK — provides per-agent cryptographic identity.

As agents become more autonomous, "trust me, I'm an agent" isn't good enough.

## The Solution

Aethyr provides verifiable identity for AI agents — like a certificate authority, but for agents instead of websites. An agent registers with Aethyr, receives a signed credential with specific capabilities, and presents that credential to any service it interacts with. The receiving service uses `ssi-verify` to check: is this agent's identity legitimate? Is the credential expired? Does this agent have permission to do what it's asking?

No shared API keys. No blockchain. No ecosystem lock-in. Just cryptographic proof that an agent is who it claims to be.

## Why Post-Quantum

Every other agent identity solution uses classical cryptography (Ed25519, RSA, secp256k1). Aethyr uses **ML-DSA-65** (NIST FIPS 204) — a post-quantum signature algorithm. Agent credentials issued today may still be in circulation when quantum computers can break classical signatures. We're not waiting for that to become a problem.

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
const parsed = parseDID('did:aethyr:console:abc123');
// { namespace: 'console', identifier: 'abc123' }
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
                                          ✓ signature valid?
                                          ✓ credential expired?
                                          ✓ capabilities match?
```

1. **Agent registers** with Aethyr and receives a signed credential
2. **Agent presents** the credential to your service
3. **Your service verifies** using `ssi-verify` and Aethyr's public key
4. **Your service checks capabilities** to decide what the agent can do

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

- [`@aethyrai/ssi`](https://github.com/aethyrai/ssi) — Full SSI protocol: identity, credentials, signing, key hierarchy
- [Aethyr](https://aethyr.ai) — Trust infrastructure for AI agents

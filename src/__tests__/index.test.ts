import { blake3 } from '@noble/hashes/blake3.js';
// We need to import from core to issue test credentials
// In real usage, verify package is standalone — these are just test helpers
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { describe, expect, it } from 'vitest';
import {
  AETHYR_ISSUER_DID,
  AETHYR_ISSUER_PUBLIC_KEY,
  checkRevocationStatus,
  matchCapabilities,
  matchCapability,
  parseDID,
  verify,
  verifyAction,
  verifyCredential,
} from '../index.js';

const SEED_42 = new Uint8Array(32).fill(42);

// Helper: derive signing key material (matches core's key-hierarchy.ts)
function deriveSigningMaterial(seed: Uint8Array): Uint8Array {
  return blake3(seed, { context: "PSAM-Key-Signing-m/1'", dkLen: 32 });
}

// Helper: create a test credential
function makeTestCredential(signingSecretKey: Uint8Array, issuerDid: string) {
  const now = new Date();
  const credentialWithoutProof = {
    '@context': ['https://www.w3.org/2018/credentials/v1', 'https://aethyr.cloud/credentials/v1'],
    type: ['VerifiableCredential', 'AethyrCapabilityCredential'],
    issuer: issuerDid,
    issuanceDate: now.toISOString(),
    expirationDate: new Date(now.getTime() + 86400000).toISOString(),
    credentialSubject: {
      id: 'did:aethyr:test:agent-subject',
      type: 'AethyrAgent',
      capabilities: ['tool:hubspot_*'],
    },
  };

  const payload = new TextEncoder().encode(canonicalJson(credentialWithoutProof));

  const signature = ml_dsa65.sign(payload, signingSecretKey);
  const proofValue = btoa(String.fromCharCode(...signature))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');

  return {
    ...credentialWithoutProof,
    proof: {
      type: 'MLDSASignature2026',
      created: now.toISOString(),
      verificationMethod: `${issuerDid}#key-signing`,
      proofPurpose: 'assertionMethod',
      proofValue,
    },
  };
}

function canonicalJson(obj: unknown): string {
  return JSON.stringify(obj, (_key, value) => {
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      const sorted: Record<string, unknown> = {};
      for (const k of Object.keys(value as Record<string, unknown>).sort()) {
        sorted[k] = (value as Record<string, unknown>)[k];
      }
      return sorted;
    }
    return value;
  });
}

describe('ssi-verify', () => {
  // Set up issuer keys
  const signingMaterial = deriveSigningMaterial(SEED_42);
  const signingKeypair = ml_dsa65.keygen(signingMaterial);
  const issuerDid = 'did:aethyr:test:issuer-abc123';

  describe('verifyCredential', () => {
    it('valid credential passes', () => {
      const cred = makeTestCredential(signingKeypair.secretKey, issuerDid);
      const result = verifyCredential(cred, signingKeypair.publicKey);
      expect(result.valid).toBe(true);
    });

    it('wrong key fails', () => {
      const wrongMaterial = deriveSigningMaterial(new Uint8Array(32).fill(99));
      const wrongKeypair = ml_dsa65.keygen(wrongMaterial);

      const cred = makeTestCredential(signingKeypair.secretKey, issuerDid);
      const result = verifyCredential(cred, wrongKeypair.publicKey);
      expect(result.valid).toBe(false);
    });

    it('rejects unsupported proof type', () => {
      const cred = makeTestCredential(signingKeypair.secretKey, issuerDid);
      cred.proof.type = 'Ed25519Signature2020';
      const result = verifyCredential(cred, signingKeypair.publicKey);
      expect(result.valid).toBe(false);
      expect(result.reason).toContain('Unsupported proof type');
    });

    it('rejects expired credential', () => {
      const cred = makeTestCredential(signingKeypair.secretKey, issuerDid);
      cred.expirationDate = new Date(Date.now() - 1000).toISOString();
      const result = verifyCredential(cred, signingKeypair.publicKey);
      expect(result.valid).toBe(false);
      expect(result.reason).toBe('Credential has expired');
    });

    it('rejects tampered credential body', () => {
      const cred = makeTestCredential(signingKeypair.secretKey, issuerDid);
      cred.credentialSubject.capabilities = ['*'];
      const result = verifyCredential(cred, signingKeypair.publicKey);
      expect(result.valid).toBe(false);
    });
  });

  describe('verifyAction', () => {
    it('valid action passes', () => {
      const payload = new TextEncoder().encode('tool:hubspot_create_contact');
      const signature = ml_dsa65.sign(payload, signingKeypair.secretKey);

      const result = verifyAction(
        { payload, signature, signerDid: issuerDid, timestamp: new Date().toISOString() },
        signingKeypair.publicKey,
      );
      expect(result.valid).toBe(true);
    });

    it('wrong key fails with reason', () => {
      const wrongMaterial = deriveSigningMaterial(new Uint8Array(32).fill(99));
      const wrongKeypair = ml_dsa65.keygen(wrongMaterial);

      const payload = new TextEncoder().encode('action');
      const signature = ml_dsa65.sign(payload, signingKeypair.secretKey);

      const result = verifyAction(
        { payload, signature, signerDid: issuerDid, timestamp: new Date().toISOString() },
        wrongKeypair.publicKey,
      );
      expect(result.valid).toBe(false);
      expect(result.reason).toBe('Invalid signature');
    });
  });

  describe('verify', () => {
    it('raw signature verification works', () => {
      const data = new TextEncoder().encode('raw data');
      const sig = ml_dsa65.sign(data, signingKeypair.secretKey);
      expect(verify(signingKeypair.publicKey, data, sig)).toBe(true);
    });
  });

  describe('parseDID', () => {
    it('parses valid DID', () => {
      const result = parseDID('did:aethyr:console:abc123');
      expect(result).toEqual({ namespace: 'console', identifier: 'abc123' });
    });

    it('returns null for invalid DID', () => {
      expect(parseDID('not-a-did')).toBeNull();
      expect(parseDID('did:other:method:id')).toBeNull();
      expect(parseDID('did:aethyr')).toBeNull();
    });

    it('returns null for empty segments', () => {
      expect(parseDID('did:aethyr::')).toBeNull();
      expect(parseDID('did:aethyr:console:')).toBeNull();
      expect(parseDID('did:aethyr::abc123')).toBeNull();
    });
  });

  describe('capability matching', () => {
    it('matchCapability works', () => {
      expect(matchCapability('tool:hubspot_*', 'tool:hubspot_create_contact')).toBe(true);
      expect(matchCapability('tool:hubspot_*', 'tool:jobtread_list')).toBe(false);
    });

    it('matchCapabilities works', () => {
      expect(matchCapabilities(['tool:hubspot_*', 'tool:jobtread_*'], 'tool:hubspot_search')).toBe(
        true,
      );
      expect(matchCapabilities(['tool:hubspot_*'], 'tool:jobtread_list')).toBe(false);
    });

    it('empty capabilities array returns false', () => {
      expect(matchCapabilities([], 'tool:anything')).toBe(false);
    });

    it('exact match works without wildcard', () => {
      expect(matchCapability('tool:hubspot_search', 'tool:hubspot_search')).toBe(true);
      expect(matchCapability('tool:hubspot_search', 'tool:hubspot_create')).toBe(false);
    });

    it('universal wildcard matches everything', () => {
      expect(matchCapability('*', 'tool:anything')).toBe(true);
    });
  });

  describe('trust authority exports', () => {
    it('AETHYR_ISSUER_PUBLIC_KEY is a 1952-byte Uint8Array', () => {
      expect(AETHYR_ISSUER_PUBLIC_KEY).toBeInstanceOf(Uint8Array);
      expect(AETHYR_ISSUER_PUBLIC_KEY.length).toBe(1952);
    });

    it('AETHYR_ISSUER_DID has correct format', () => {
      expect(AETHYR_ISSUER_DID).toMatch(/^did:aethyr:authority:[a-f0-9]{64}$/);
    });

    it('checkRevocationStatus returns null for non-existent credential', async () => {
      const result = await checkRevocationStatus('nonexistent', 'http://localhost:99999');
      expect(result).toBeNull();
    });
  });
});

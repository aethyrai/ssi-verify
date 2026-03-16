import { blake3 } from '@noble/hashes/blake3.js';
// We need to import from core to issue test credentials
// In real usage, verify package is standalone — these are just test helpers
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { describe, expect, it } from 'vitest';
import {
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

    it('wrong key fails', () => {
      const wrongMaterial = deriveSigningMaterial(new Uint8Array(32).fill(99));
      const wrongKeypair = ml_dsa65.keygen(wrongMaterial);

      const payload = new TextEncoder().encode('action');
      const signature = ml_dsa65.sign(payload, signingKeypair.secretKey);

      const result = verifyAction(
        { payload, signature, signerDid: issuerDid, timestamp: new Date().toISOString() },
        wrongKeypair.publicKey,
      );
      expect(result.valid).toBe(false);
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
  });
});

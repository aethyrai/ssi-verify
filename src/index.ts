/**
 * @aethyrai/ssi-verify — Lightweight SSI Verification
 *
 * Verification-only library for checking Aethyr SSI credentials
 * and action signatures. No issuance, no key management, no custody.
 *
 * Designed to be embedded in any runtime — MCP servers, PicoClaw agents,
 * AIOS nodes, or any service that needs to verify Aethyr credentials.
 */

import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';

// ─── Types (subset of @aethyrai/ssi) ───────────────────────────

export interface VerifiableCredential {
  '@context': string[];
  type: string[];
  issuer: string;
  issuanceDate: string;
  expirationDate?: string;
  credentialSubject: Record<string, unknown>;
  proof: {
    type: string;
    created: string;
    verificationMethod: string;
    proofPurpose: string;
    proofValue: string;
  };
}

export interface SignedAction {
  payload: Uint8Array;
  signature: Uint8Array;
  signerDid: string;
  timestamp: string;
}

export interface VerificationResult {
  valid: boolean;
  reason?: string;
}

// ─── Credential Verification ────────────────────────────────────

/**
 * Verify a Verifiable Credential's signature and expiry.
 *
 * Does NOT check revocation — that is implementation-specific.
 *
 * @param credential - The credential to verify
 * @param issuerPublicKey - The issuer's ML-DSA-65 signing public key (1,952 bytes)
 * @returns Verification result
 */
export function verifyCredential(
  credential: VerifiableCredential,
  issuerPublicKey: Uint8Array,
): VerificationResult {
  // Check proof type
  if (credential.proof.type !== 'MLDSASignature2026') {
    return { valid: false, reason: `Unsupported proof type: ${credential.proof.type}` };
  }

  // Check expiry
  if (credential.expirationDate) {
    const expiry = new Date(credential.expirationDate);
    if (expiry <= new Date()) {
      return { valid: false, reason: 'Credential has expired' };
    }
  }

  // Reconstruct payload (credential without proof)
  const { proof, ...credentialWithoutProof } = credential;

  const payload = new TextEncoder().encode(canonicalJson(credentialWithoutProof));

  // Decode signature
  const signature = base64UrlToUint8Array(proof.proofValue);

  // Verify ML-DSA-65 signature
  try {
    const valid = ml_dsa65.verify(signature, payload, issuerPublicKey);
    if (!valid) {
      return { valid: false, reason: 'Invalid signature' };
    }
    return { valid: true };
  } catch {
    return { valid: false, reason: 'Signature verification failed' };
  }
}

// ─── Action Signature Verification ──────────────────────────────

/**
 * Verify a signed action against a public key.
 *
 * @param signedAction - The signed action to verify
 * @param signingPublicKey - The signer's ML-DSA-65 public key (1,952 bytes)
 * @returns Verification result
 */
export function verifyAction(
  signedAction: SignedAction,
  signingPublicKey: Uint8Array,
): VerificationResult {
  try {
    const valid = ml_dsa65.verify(signedAction.signature, signedAction.payload, signingPublicKey);
    return { valid };
  } catch {
    return { valid: false, reason: 'Signature verification failed' };
  }
}

// ─── Raw Signature Verification ─────────────────────────────────

/**
 * Verify an ML-DSA-65 signature against a public key.
 *
 * @param publicKey - ML-DSA-65 verifying key (1,952 bytes)
 * @param data - The original data that was signed
 * @param signature - The signature to verify (3,309 bytes)
 * @returns true if valid
 */
export function verify(publicKey: Uint8Array, data: Uint8Array, signature: Uint8Array): boolean {
  try {
    return ml_dsa65.verify(signature, data, publicKey);
  } catch {
    return false;
  }
}

// ─── Capability Matching ────────────────────────────────────────

/**
 * Check if a granted capability matches a requested operation.
 * Supports glob-style wildcards.
 *
 * @param granted - The capability string from a credential (e.g., "tool:hubspot_*")
 * @param requested - The operation being requested (e.g., "tool:hubspot_create_contact")
 * @returns true if the granted capability covers the requested operation
 */
export function matchCapability(granted: string, requested: string): boolean {
  if (granted === requested) {
    return true;
  }
  if (granted === '*') {
    return true;
  }
  if (granted.endsWith('*')) {
    const prefix = granted.slice(0, -1);
    return requested.startsWith(prefix);
  }
  return false;
}

/**
 * Check if any granted capability matches a requested operation.
 *
 * @param granted - Array of capability strings from credentials
 * @param requested - The operation being requested
 * @returns true if any granted capability covers the requested operation
 */
export function matchCapabilities(granted: string[], requested: string): boolean {
  return granted.some((cap) => matchCapability(cap, requested));
}

// ─── DID Parsing ────────────────────────────────────────────────

/**
 * Parse a did:aethyr: DID string.
 *
 * @param did - DID string (e.g., "did:aethyr:console:a7f3b2c1...")
 * @returns Parsed components or null if invalid
 */
export function parseDID(did: string): { namespace: string; identifier: string } | null {
  const parts = did.split(':');
  if (parts.length !== 4 || parts[0] !== 'did' || parts[1] !== 'aethyr') {
    return null;
  }
  return { namespace: parts[2], identifier: parts[3] };
}

// ─── Utilities ──────────────────────────────────────────────────

/** Recursively sort all object keys for deterministic serialization. */
function canonicalJson(obj: unknown): string {
  return JSON.stringify(obj, (_key, value) => {
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      const sorted: Record<string, unknown> = {};
      for (const k of Object.keys(value).sort()) {
        sorted[k] = value[k];
      }
      return sorted;
    }
    return value;
  });
}

function base64UrlToUint8Array(base64url: string): Uint8Array {
  const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

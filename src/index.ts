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

// ─── Aethyr Trust Authority ─────────────────────────────────────

/**
 * Aethyr Trust Authority's ML-DSA-65 signing public key.
 *
 * This is the key used to sign credentials issued by the
 * Aethyr Agent Registry (https://registry.aethyr.cloud).
 *
 * Usage:
 *   import { verifyCredential, AETHYR_ISSUER_PUBLIC_KEY } from '@aethyrai/ssi-verify';
 *   const result = verifyCredential(credential, AETHYR_ISSUER_PUBLIC_KEY);
 *
 * Updated on key rotation. Verify at: https://registry.aethyr.cloud/v1/issuer
 */
export const AETHYR_ISSUER_PUBLIC_KEY: Uint8Array = base64UrlToUint8Array(
  'HcWIKKMNGx4bbN5FajHzE4Z2BUaiZSk_gaf3P7euinJtUXiYro0PBpbeCkdYryk7ykeNH4AEGJeR00SF5SP2lAoPbQU_CEtXMVaa-ewd_61UE4JL9V2D2Jgqo_EC7gjHi6OoGueEuKWw6QjBD5nSGqElOeFh7tGEcOOzVjaBAuISDhkGMa0u8mbdMWDr-60vNAIxstQ1YjShZRNKEdtOvvKbGIKqSfg5qaEX1XIMhjDjadPvxD-vXV2m6iUIeVWvSG0Oc9y3Bg2dSE-op5UOjh7d6ZQWSSN0W1T5cdJWfiyqG2eg-HsjXsA-5Z7N9eZPo3M1syGdK453O9BSQf5yokrPjfWU0YOuH80Bcy86tEG6QECvIrcKZaTJMpX0RvUcnVRCVlK8l8oLZKHJLOVRtxYKRXB2KjYX3h8Z6FfVHNcI6wqTLVUCgfAZS6AdXE6jkPd2kr1MfrfyzZrIQ0EubmPr5WrwpfSM0BNmGHCuGtQR6FVw9Gsccropkw-c9UTAlWumI5rcbGsUrGXMtBdNIKNsaNVEY7VAFSyM-pLp-gvwJKptRK2yzMiTRNNO1Fnhl7oLMx6TnoiMDa4NZWjq_SuWke4DErOX4NDJwcp6PbQCFAIG5Pi9uR45BgrGlj6r-vyjSW6YaoMZY1rRZRUxPogHSLKOTtQ6m8fovPCAI4IglE3EOyAeJB3i5KrX0q8ZRPaRekwgbHvzp3AdVJuhc40KtRUWaTLd1rI3b-rGhO_-pM2tR4A-Jm9Mc54T0W9uPnV6MislCWq2WdTF_foJEWJUbJe1oqOjRMFpRLCVRBgxoNl8RXGmWs2Cog1hTa7M1B6PEBRw5vYz1D44NgYZZkJSDzNj27RSKWxLNz2klkfSlGZgoCOWfXMRK1L9iwYuBS5nv2SO5tft1hljgpNA4AFDnY-qO2w7TBFv-2gZ68ejbqBGuTns8WaSdvUt-jpfsvEkDAx2M72ZAXiQhDTYMECCXG2GJg_e6mcAnYqcjpYiKxCOjJhs0XfKoT1ih-fbMLR6if--7VgRIg5zMgFC2laywF-tMadN2xDRqOd5DWFuwuGaXwREzH1knBLsV5Mh90kVOefXN0gf69jc_S77Q-5e-eJzsBVcEmofCOB2_M_aWVc94iZgTyTSfOlEzyU2rHTYRQISysS541fSi9_73X7aGOo38r5LVjUe5Y_SePlbemRhjFhIrc6Bf3rezYE58_q7vaMuOTT6ZdZ1MCE5A-2L7HOk895SVszrExzh1sJoKOvLxRRqe_s3vSE7mo4DPsKNRTWYoOTreHOxv7cVAXHc508eUxXVMtq4XeOata9HWwqGU-qQFKZEJIOvJWoESuHQqT88jl4wTEIWGNlKuTh9pwxTJqr3sSU-Po-hCMLW_ZqaPFXo08jQd87iHaRAgGvieWnz4tEJJH5TwjqH50a4gV69xGYijOxqMR_Uv9SUhliC09_SyWqMUJtwV5MggJTKbzvJ0dqTvVYewK_78AOooIaHqjRfzVwpEtNeHiJw-Izslb0BmiIAQwCcbhjM2VD5vXcwl-nXatVtIItEqRf_70VCpbpLgymKNS2Pr3fn3O3gzezt185eqn6YIXqBq4umDgacII7dfX1Y52w_Yzb9yI7eCMa7v8BAQmWjr9Yotte2eAW3TFs8S_nevLeb7Av3DFqKoQTP65C6cdLG3gj_0iRLDz-lGm5f72A_a6Sko6mzGx8OX_xPWKDxbXiJA3OQXi7YYSVbYMLTYtC_3TRq38jcfV94QojS6L1UhDWPZx799_VaTDH1BBI8L3XVqiLf-aH5aQhZKgL7CMRYY0MJGo-9-bdBpK9ImoWeXlHLBop42tB1KrIag30bumrD1mNcGJPm-KYCTD3-9xBVvsCzLoaKWHWHE3zGlmKXQUeXhLvkdQIeCOaYBjhilxUXzIxS9hPppno9nTZS5zENwbyfPzRRL26zV5zMk4H0gdqLS_k--clebLRu6uKcciXfpkoYmS_vIWNr14xIoKiFba9inYrmhG46YJFl0GukxVQrI3K0WfNNJ9YrzZ5hcCWVXHbOvGtufpQ0l9VaAadTo2suC4-7PC-Ay-ixN4JiB7jZxph2i81eY2Kh3XH2rm94E0KooruRWZ5HKxJ2b_VYTvJAuRJYhVNNuCIgrM98JeYMsuDMAfyeiIJaf2u63FfE9mIh1j1_6v6DHHgYmDGU3k5y6-OcQXl2tkwlOEjA8G3GIUj8WVJSO8RqZJ73CTlXY-s8Awhbiz-74d96PlIQ-ge7saFwXe8aFf2fiO1cUR2_3LxxQMmhcfvvdCwaEIm03B0UJ17EuTtvT4yWn0souHZb5KRSp872rhxU7dlbY5ylrOB72SzkU4mLOu72pkwWq70i72qoX2WRx2eqIkLCZSK-KQJBwukfI4MvVDxmSM_HCz_bcxXsMrcShzirmLnwDSb3PYC7UxPuIXe7_elpVG79qWRY3Ee7fiXf03Q3O6ODJqMb-9IwAb0OA2HSWu_KV_nYmwBQrqjmTYQi2s9TfUmr50bx2bSRP89_GW9HK2qRPZl3hp8fkd64T5Ok7b1BRMj4KQc6CJo4OLqDo-GszfILpdRvYlfodbSFJVVcUEM',
);

/** Aethyr Trust Authority DID */
export const AETHYR_ISSUER_DID =
  'did:aethyr:authority:1be222754b23ade38835f8d55bf02ace9403420a3e9b4169db3be0c38af3ed66';

// ─── Revocation Check ──────────────────────────────────────────

/**
 * Check credential revocation status against the Aethyr registry.
 * This is optional — verifyCredential() works fully offline.
 *
 * @param credentialId - The credential's registration ID
 * @param registryUrl - Registry URL (default: https://registry.aethyr.cloud)
 * @returns Status or null if unreachable
 */
export async function checkRevocationStatus(
  credentialId: string,
  registryUrl = 'https://registry.aethyr.cloud',
): Promise<{ status: string; revokedAt: string | null; revokedReason: string | null } | null> {
  try {
    const response = await fetch(`${registryUrl}/v1/status/${credentialId}`);
    if (!response.ok) {
      return null;
    }
    return (await response.json()) as {
      status: string;
      revokedAt: string | null;
      revokedReason: string | null;
    };
  } catch {
    return null;
  }
}

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
    if (!valid) {
      return { valid: false, reason: 'Invalid signature' };
    }
    return { valid: true };
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
 * Supports trailing wildcards (e.g., "tool:hubspot_*").
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
  if (parts.length !== 4 || parts[0] !== 'did' || parts[1] !== 'aethyr' || !parts[2] || !parts[3]) {
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

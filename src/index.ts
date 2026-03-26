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
  'P_U7pZi86eLzN6TM1A3R7PqmR5Ff6OIh3imFKx1M3iulfyhouv4EUayCxH9FepoyhNtiMeMo7EC4ZDLwOkA-ySIhtuzJU_KWfPr6UNerFzZlYCzNjAjz_u6D7psi-3wefC6MyhcVxD8OIFfn253Qb7W99IL9_hc6RVsYuHdFDsXhgqzAsepMeCalzxHBQkn6wKegEpqNxFS8QwwW_h2c4RnTafdVZ-aQw_IHWPI2kMFadYKHbF06vSQjguC217dGrRje4FEZaFfy_DXrv8M6w1dDQ5nH_Tq4a6cqezgRhPbGETAsD13OK6GDQOoD0_aHcFZdvV76VGzBANkbAiRpTa8HXZvmYuXqYR6ue0GDVE020ljd_yjG0NigIBNEpMhcFpD5gY7RPgUhwstl3Uqma18Pn-_boEOcRZr9tuAcr5Q-0Kcv8_Lbh7NtIYwXTZYZtlBxXFrWPEjqMqASwexKasbtnuXh33sZwmiT2UAKMeMeD9-RR7WzxonmhlChThIAxg7fD0Z4kANMu72wM0j3bzKeTyJM-ccQlwH4jHM3iu3OheX17MLqjle0qrnLVNy4JeN2wXUUJNY2YgjD1h_2zL9Pv4ZRNdt9vWA9CZLikXhTwOtpt5tXK3CU78pux7RlKX9RCDK2f59YnpfnPpi8gpcOQeCtAoeY7t-a351fUgFGul_5nAyfUi-7aiCWBKYYLyArVIzpF7tNy_AObdM1k9KyRRrXV9DJOzsSDlO7wYyaANtx8i70aOZlh_eF_PbpQNGKa3YTqNA5L7iD18OjMIZW0n2nYXNsamV0LOXgHlZhYNJBZO7466S-gKshqkvgLxs8wteQkGz9LXhNziHEBchh8_3ctyyzUCSb6u24QkseA8EwcX6mbx-Eo0JJVLWva3de4Jyp-f4pigZrSnF4USNqsaX9O6iPR0TlYna4Y_AVKrGSD9z5wgbrklsm0qm48Hf_qGcp70n5U4vw_MlTHCNmZX4x2aMNxmUP-505SyE75TLONzc8I8urykJW_npij4BvzEOhVUsNN5sp3lxXSeq2sXQnEYJH7YzV-pZle7YNKbqBpKyxCmK1BLGJf3zxzgqNA7V30v15LqKFRVOaGqliqhWROs_XlYfPig9kAHIQ3IR0SLLeqw1KFgdnY-p_TV5HL8_cvOsCvJRgP7kGxikqdNvcrTrLCj0KtgaKD8vAia61RjsH7A8aUQfTtnkOGEQc8BcHsNsNyjMvR7DS-K4qtpclfj4smERhUxyAAP0cauwRjtM_eTrL_RVWcgVcEdydmhnE0uoTnbn7Os6CHqrOqjlEJfP4ttZMJBDE41SLUFzA9zrxNEDEMyBCiEZpenhHdGvvjgb4zkIliPW_mq-8oPNAUAS5pn8WrLxhd86XTgLb4T0exjfTgU_9c84xaxCsaTibyw8XsSi7In_UwgioPBtiGRoqeweaKtcj8NFOO5vL0lJELg-TMqo_hy2LA5swz3zjGOsQYFvR089a8N6mk0EMLFoRta07n-wQn0siWFnaMmte7pmDNsT4wBaR3ldE5gafj-njNRyzS4gps3eEmuRVBx83D4iKEYFcMEiO_0tkI-fh1BaNQvPByxRVl-z3Y0qQSqBgLhVkKhXDYW_OVVicHmd4YGNG9yJQFweP1ppIsxyRAVmW7KGCfqOxKwfzxxjD0-hRrkV22ody0u6w9yLiKGgfkgECbWIUEGo86RerQ2mQOR0CYLj3bd3uXyNjbQlylbUCyESe8KT-A1F59HpKObQNzFcoJEKK_9h51xp5j1yj6pEzSmrn4keHki6X1PhzVj0D02E-zTLGtuzPauqZus0Qb0yyg2s7puLQ5h9i8TmWUegpGloMk7-dtu8gp7mkcgMKdF1ne5SKASl6YZIyVQUSJq0n4k148DLmX9Axp07BoTL7CC7Tf2SKyC0tWF8KMlQa_uQbuxvvOr986UE8P92h5uHskDIUunQKh-v3bClxZ5hhcNXQkP-FPJzqKdEPZFtaf2Fb_ZllBq3Y5RVgiNCKTSembnrCa9l-abumHsMmX87NZLk1FVNJMEYFBUQsgU1uibYZ6yQxiWyoOZKJA3toSd77ojBuANxq-r-fpIXfj7HcHkTGJTHJoZsQu7V_vY9kEU7wALgGhS7g-dI9TnvdntQAkidjFL80F6ZfpcrSz2MR5M3xC1JN9tymXXXAWgzKk_TdKCPmmMsr1vcf_qBNSlO-HuwR_-GsY5i_0a_Aivy1q3r5qBfKFWIH5-NfBvbbA-KrYMcOkRCXEaQPlUuzAz72gyKTxwrvvhAqVdglA7UWkqrap3lFarx8VeuBHUYK4iodWrjUi9CEK9P4AtYQZ4AxhzSYWmSkphKOOcsJuF1-NN8C_BiMC4hHBuJm-4fDLlFMwA7GqcoqZCORAmJ2s1Z029sQT_5YPOsBc2uaV11Ons3yskinuIqHOYZBz6PUDhPFEEarTM0AIpasIynvY3XWihiM58vU5nE8gAZ-lX1-ndNFipyqKeTEN8j0yGEpMCsIZ1D6mG0W2fqhImTepc8W1p27KapLHI4XPFnlUfRxCrVnlDQdDvPwTH-Fc75cozZs1XBsGeGbZSy4jdZ_ZxqB3ROhvVI',
);

/** Aethyr Trust Authority DID */
export const AETHYR_ISSUER_DID =
  'did:aethyr:authority:9cbc1e38da3b63d3b878ecc56cdb9431381865d8f5411aa03f5058349283d61f';

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

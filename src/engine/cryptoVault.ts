import { PseudonymMapping } from '../types/pii';

export interface EncryptedVaultBundle {
  version: 2;
  algorithm: 'AES-GCM';
  keyLengthBits: 256;
  kdf: 'PBKDF2-SHA256';
  iterations: number;
  saltBase64: string;
  ivBase64: string;
  ciphertextBase64: string;
  createdAt: string;
}

const PBKDF2_ITERATIONS = 600_000;
const MIN_PASSPHRASE_LENGTH = 8;

function toBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i] ?? 0);
  }
  return btoa(binary);
}

function fromBase64(b64: string): Uint8Array<ArrayBuffer> {
  const binary = atob(b64);
  const buffer = new ArrayBuffer(binary.length);
  const view = new Uint8Array(buffer);
  for (let i = 0; i < binary.length; i++) {
    view[i] = binary.charCodeAt(i);
  }
  return view;
}

function buildVaultAad(version: number, iterations: number, createdAt: string): Uint8Array<ArrayBuffer> {
  const encoded = new TextEncoder().encode(`ciphershield:v${version}:PBKDF2-SHA256:${iterations}:${createdAt}`);
  const buf = new ArrayBuffer(encoded.byteLength);
  new Uint8Array(buf).set(encoded);
  return new Uint8Array(buf);
}

async function deriveAesKey(passphrase: string, salt: Uint8Array<ArrayBuffer>, iterations: number): Promise<CryptoKey> {
  const baseKey = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(passphrase),
    'PBKDF2',
    false,
    ['deriveKey'],
  );

  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

function isValidMappingArray(payload: unknown): payload is PseudonymMapping[] {
  if (!Array.isArray(payload)) return false;
  return payload.every((item) => {
    if (!item || typeof item !== 'object') return false;
    const candidate = item as Record<string, unknown>;
    return (
      typeof candidate['token'] === 'string' &&
      typeof candidate['category'] === 'string' &&
      typeof candidate['normalizedKey'] === 'string' &&
      typeof candidate['sampleValue'] === 'string' &&
      typeof candidate['occurrences'] === 'number'
    );
  });
}

/**
 * Encrypts the volatile pseudonym mapping ledger locally using PBKDF2-SHA256 (600k iterations) + AES-256-GCM with AAD binding.
 */
export async function encryptPseudonymLedger(
  mappings: PseudonymMapping[],
  passphrase: string,
  iterations = PBKDF2_ITERATIONS,
): Promise<EncryptedVaultBundle> {
  if (!passphrase || passphrase.length < MIN_PASSPHRASE_LENGTH) {
    throw new Error(`Passphrase must be at least ${MIN_PASSPHRASE_LENGTH} characters.`);
  }

  const salt = new Uint8Array(new ArrayBuffer(16));
  crypto.getRandomValues(salt);
  const iv = new Uint8Array(new ArrayBuffer(12));
  crypto.getRandomValues(iv);

  const createdAt = new Date().toISOString();
  const additionalData = buildVaultAad(2, iterations, createdAt);
  const aesKey = await deriveAesKey(passphrase, salt, iterations);
  const plaintext = new TextEncoder().encode(JSON.stringify(mappings));

  const cipherBuffer = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData },
    aesKey,
    plaintext,
  );

  return {
    version: 2,
    algorithm: 'AES-GCM',
    keyLengthBits: 256,
    kdf: 'PBKDF2-SHA256',
    iterations,
    saltBase64: toBase64(salt),
    ivBase64: toBase64(iv),
    ciphertextBase64: toBase64(new Uint8Array(cipherBuffer)),
    createdAt,
  };
}

/**
 * Decrypts a .ciphershield.key.json bundle strictly inside browser memory and validates shape.
 */
export async function decryptPseudonymLedger(
  bundle: EncryptedVaultBundle,
  passphrase: string,
): Promise<PseudonymMapping[]> {
  if (
    !bundle ||
    bundle.algorithm !== 'AES-GCM' ||
    !bundle.saltBase64 ||
    !bundle.ivBase64 ||
    !bundle.ciphertextBase64 ||
    typeof bundle.iterations !== 'number' ||
    bundle.iterations < 10_000
  ) {
    throw new Error('Invalid CipherShield encrypted vault format.');
  }

  try {
    const salt = fromBase64(bundle.saltBase64);
    const iv = fromBase64(bundle.ivBase64);
    const ciphertext = fromBase64(bundle.ciphertextBase64);
    if (salt.byteLength !== 16 || iv.byteLength !== 12) {
      throw new Error('Invalid cryptographic salt/IV dimensions.');
    }

    const additionalData = buildVaultAad(bundle.version ?? 2, bundle.iterations, bundle.createdAt ?? '');
    const aesKey = await deriveAesKey(passphrase, salt, bundle.iterations);
    const plainBuffer = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv, additionalData },
      aesKey,
      ciphertext,
    );

    const parsed: unknown = JSON.parse(new TextDecoder().decode(plainBuffer));
    if (!isValidMappingArray(parsed)) {
      throw new Error('Corrupted mapping payload.');
    }
    return parsed;
  } catch {
    throw new Error('Decryption failed: incorrect passphrase or tampered key file.');
  }
}

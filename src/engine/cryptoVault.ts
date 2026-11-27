import { PseudonymMapping } from '../types/pii';

export interface EncryptedVaultBundle {
  version: 1;
  algorithm: 'AES-GCM';
  keyLengthBits: 256;
  kdf: 'PBKDF2-SHA256';
  iterations: number;
  saltBase64: string;
  ivBase64: string;
  ciphertextBase64: string;
  createdAt: string;
}

const PBKDF2_ITERATIONS = 100_000;

function toBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
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

async function deriveAesKey(passphrase: string, salt: Uint8Array<ArrayBuffer>): Promise<CryptoKey> {
  const baseKey = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(passphrase),
    'PBKDF2',
    false,
    ['deriveKey'],
  );

  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations: PBKDF2_ITERATIONS,
      hash: 'SHA-256',
    },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

/**
 * Encrypts the volatile pseudonym mapping ledger locally using PBKDF2-SHA256 + AES-256-GCM.
 */
export async function encryptPseudonymLedger(
  mappings: PseudonymMapping[],
  passphrase: string,
): Promise<EncryptedVaultBundle> {
  if (!passphrase || passphrase.length < 4) {
    throw new Error('Passphrase must be at least 4 characters.');
  }

  const saltBuf = new ArrayBuffer(16);
  const salt = new Uint8Array(saltBuf);
  crypto.getRandomValues(salt);

  const ivBuf = new ArrayBuffer(12);
  const iv = new Uint8Array(ivBuf);
  crypto.getRandomValues(iv);

  const aesKey = await deriveAesKey(passphrase, salt);
  const plaintext = new TextEncoder().encode(JSON.stringify(mappings));

  const cipherBuffer = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, plaintext);

  return {
    version: 1,
    algorithm: 'AES-GCM',
    keyLengthBits: 256,
    kdf: 'PBKDF2-SHA256',
    iterations: PBKDF2_ITERATIONS,
    saltBase64: toBase64(salt),
    ivBase64: toBase64(iv),
    ciphertextBase64: toBase64(new Uint8Array(cipherBuffer)),
    createdAt: new Date().toISOString(),
  };
}

/**
 * Decrypts a previously exported .ciphershield.key.json bundle strictly inside browser memory.
 */
export async function decryptPseudonymLedger(
  bundle: EncryptedVaultBundle,
  passphrase: string,
): Promise<PseudonymMapping[]> {
  if (!bundle || bundle.algorithm !== 'AES-GCM' || !bundle.saltBase64 || !bundle.ivBase64 || !bundle.ciphertextBase64) {
    throw new Error('Invalid CipherShield encrypted vault format.');
  }

  const salt = fromBase64(bundle.saltBase64);
  const iv = fromBase64(bundle.ivBase64);
  const ciphertext = fromBase64(bundle.ciphertextBase64);
  const aesKey = await deriveAesKey(passphrase, salt);

  try {
    const plainBuffer = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, ciphertext);
    const decoded = new TextDecoder().decode(plainBuffer);
    const parsed = JSON.parse(decoded);
    if (!Array.isArray(parsed)) {
      throw new Error('Corrupted mapping payload.');
    }
    return parsed as PseudonymMapping[];
  } catch {
    throw new Error('Decryption failed: incorrect passphrase or tampered key file.');
  }
}

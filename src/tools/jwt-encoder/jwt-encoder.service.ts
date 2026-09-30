import { Base64 } from 'js-base64';
import { asn1, pki } from 'node-forge';

export { encodeJwt, generateKeyPair, isSymmetricAlgorithm, JWT_ALGORITHMS };
export type { JwtAlgorithm };

const JWT_ALGORITHMS = [
  'HS256',
  'HS384',
  'HS512',
  'RS256',
  'RS384',
  'RS512',
  'PS256',
  'PS384',
  'PS512',
  'ES256',
  'ES384',
  'ES512',
  'none',
] as const;

type JwtAlgorithm = typeof JWT_ALGORITHMS[number];

const EC_CURVES: Record<string, string> = {
  256: 'P-256',
  384: 'P-384',
  512: 'P-521',
};

function isSymmetricAlgorithm(algorithm: JwtAlgorithm) {
  return algorithm.startsWith('HS') || algorithm === 'none';
}

function getAlgorithmParams(algorithm: JwtAlgorithm) {
  const family = algorithm.slice(0, 2);
  const bits = algorithm.slice(2);
  const hash = `SHA-${bits}`;

  if (family === 'HS') {
    return { importParams: { name: 'HMAC', hash }, signParams: { name: 'HMAC' } };
  }

  if (family === 'RS') {
    return { importParams: { name: 'RSASSA-PKCS1-v1_5', hash }, signParams: { name: 'RSASSA-PKCS1-v1_5' } };
  }

  if (family === 'PS') {
    return { importParams: { name: 'RSA-PSS', hash }, signParams: { name: 'RSA-PSS', saltLength: Number(bits) / 8 } };
  }

  if (family === 'ES') {
    return { importParams: { name: 'ECDSA', namedCurve: EC_CURVES[bits] }, signParams: { name: 'ECDSA', hash } };
  }

  throw new Error(`Unsupported algorithm: ${algorithm}`);
}

function base64UrlEncodeJson(value: unknown) {
  return Base64.encode(JSON.stringify(value), true);
}

function stringToBytes(str: string) {
  return Uint8Array.from(str, char => char.charCodeAt(0));
}

function pemToPkcs8Der(pem: string) {
  const trimmedPem = pem.trim();

  if (trimmedPem.includes('BEGIN RSA PRIVATE KEY')) {
    // PKCS#1 key (e.g. from the RSA key pair generator tool), Web Crypto only accepts PKCS#8
    const privateKeyInfo = pki.wrapRsaPrivateKey(pki.privateKeyToAsn1(pki.privateKeyFromPem(trimmedPem)));
    return stringToBytes(asn1.toDer(privateKeyInfo).getBytes());
  }

  if (trimmedPem.includes('BEGIN EC PRIVATE KEY')) {
    throw new Error('SEC1 EC keys are not supported, convert it to PKCS#8 with: openssl pkcs8 -topk8 -nocrypt -in key.pem');
  }

  const match = trimmedPem.match(/-----BEGIN PRIVATE KEY-----([\s\S]+?)-----END PRIVATE KEY-----/);

  if (!match) {
    throw new Error('The private key must be in PEM format (-----BEGIN PRIVATE KEY-----)');
  }

  return Base64.toUint8Array(match[1].replace(/\s/g, ''));
}

function derToPem(der: ArrayBuffer, label: string) {
  const base64 = Base64.fromUint8Array(new Uint8Array(der));
  const lines = base64.match(/.{1,64}/g) ?? [];

  return [`-----BEGIN ${label}-----`, ...lines, `-----END ${label}-----`].join('\n');
}

async function importSigningKey({
  algorithm,
  secret,
  isSecretBase64Encoded,
  privateKeyPem,
}: {
  algorithm: JwtAlgorithm
  secret: string
  isSecretBase64Encoded: boolean
  privateKeyPem: string
}) {
  const { importParams } = getAlgorithmParams(algorithm);

  if (isSymmetricAlgorithm(algorithm)) {
    if (secret.length === 0) {
      throw new Error('The secret cannot be empty');
    }

    const keyBytes = isSecretBase64Encoded ? Base64.toUint8Array(secret) : new TextEncoder().encode(secret);
    return crypto.subtle.importKey('raw', keyBytes, importParams, false, ['sign']);
  }

  try {
    return await crypto.subtle.importKey('pkcs8', pemToPkcs8Der(privateKeyPem), importParams, false, ['sign']);
  }
  catch (error) {
    if (error instanceof Error && error.message.includes('openssl')) {
      throw error;
    }

    throw new Error(`Invalid private key for ${algorithm}`);
  }
}

async function encodeJwt({
  header,
  payload,
  algorithm,
  secret = '',
  isSecretBase64Encoded = false,
  privateKeyPem = '',
}: {
  header: Record<string, unknown>
  payload: Record<string, unknown>
  algorithm: JwtAlgorithm
  secret?: string
  isSecretBase64Encoded?: boolean
  privateKeyPem?: string
}) {
  const signingInput = `${base64UrlEncodeJson({ ...header, alg: algorithm })}.${base64UrlEncodeJson(payload)}`;

  if (algorithm === 'none') {
    return `${signingInput}.`;
  }

  const key = await importSigningKey({ algorithm, secret, isSecretBase64Encoded, privateKeyPem });
  const { signParams } = getAlgorithmParams(algorithm);
  const signature = await crypto.subtle.sign(signParams, key, new TextEncoder().encode(signingInput));

  return `${signingInput}.${Base64.fromUint8Array(new Uint8Array(signature), true)}`;
}

async function generateKeyPair({ algorithm }: { algorithm: JwtAlgorithm }) {
  const { importParams } = getAlgorithmParams(algorithm);
  const generationParams = importParams.name === 'ECDSA'
    ? importParams
    : { ...importParams, modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]) };

  const { privateKey, publicKey } = await crypto.subtle.generateKey(generationParams, true, ['sign', 'verify']) as CryptoKeyPair;

  return {
    privateKeyPem: derToPem(await crypto.subtle.exportKey('pkcs8', privateKey), 'PRIVATE KEY'),
    publicKeyPem: derToPem(await crypto.subtle.exportKey('spki', publicKey), 'PUBLIC KEY'),
  };
}

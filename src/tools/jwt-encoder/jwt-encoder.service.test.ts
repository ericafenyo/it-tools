import { describe, expect, it } from 'vitest';
import { Base64 } from 'js-base64';
import { pki } from 'node-forge';
import { type JwtAlgorithm, encodeJwt, generateKeyPair } from './jwt-encoder.service';

const header = { alg: 'HS256', typ: 'JWT' };
const payload = { sub: '1234567890', name: 'John Doe', iat: 1516239022 };

async function verifyWithPublicKey({ token, algorithm, publicKeyPem }: { token: string; algorithm: JwtAlgorithm; publicKeyPem: string }) {
  const [encodedHeader, encodedPayload, encodedSignature] = token.split('.');
  const bits = algorithm.slice(2);
  const der = Base64.toUint8Array(publicKeyPem.replace(/-----[A-Z ]+-----|\s/g, ''));

  const params = {
    RS: { import: { name: 'RSASSA-PKCS1-v1_5', hash: `SHA-${bits}` }, verify: { name: 'RSASSA-PKCS1-v1_5' } },
    PS: { import: { name: 'RSA-PSS', hash: `SHA-${bits}` }, verify: { name: 'RSA-PSS', saltLength: Number(bits) / 8 } },
    ES: {
      import: { name: 'ECDSA', namedCurve: { 256: 'P-256', 384: 'P-384', 512: 'P-521' }[bits] },
      verify: { name: 'ECDSA', hash: `SHA-${bits}` },
    },
  }[algorithm.slice(0, 2)]!;

  const key = await crypto.subtle.importKey('spki', der, params.import, false, ['verify']);

  return crypto.subtle.verify(
    params.verify,
    key,
    Base64.toUint8Array(encodedSignature),
    new TextEncoder().encode(`${encodedHeader}.${encodedPayload}`),
  );
}

describe('jwt-encoder', () => {
  describe('encodeJwt', () => {
    it('produces the same token as jwt.io for HS256', async () => {
      expect(await encodeJwt({ header, payload, algorithm: 'HS256', secret: 'your-256-bit-secret' })).toBe(
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
      );
    });

    it('supports base64 encoded secrets', async () => {
      const token = await encodeJwt({ header, payload, algorithm: 'HS256', secret: 'eW91ci0yNTYtYml0LXNlY3JldA==', isSecretBase64Encoded: true });

      expect(token.endsWith('.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c')).toBe(true);
    });

    it('overrides the alg claim of the header with the selected algorithm', async () => {
      const token = await encodeJwt({ header, payload, algorithm: 'HS512', secret: 'secret' });
      const decodedHeader = JSON.parse(Base64.decode(token.split('.')[0]));

      expect(decodedHeader).toEqual({ alg: 'HS512', typ: 'JWT' });
      expect(Base64.toUint8Array(token.split('.')[2])).toHaveLength(64);
    });

    it('encodes non-ascii characters as utf-8', async () => {
      const token = await encodeJwt({ header, payload: { name: 'Éric 🚀' }, algorithm: 'none' });

      expect(JSON.parse(Base64.decode(token.split('.')[1]))).toEqual({ name: 'Éric 🚀' });
    });

    it('produces an unsigned token for the none algorithm', async () => {
      const token = await encodeJwt({ header, payload, algorithm: 'none' });

      expect(token).toBe('eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.');
    });

    it('throws when the secret is empty', async () => {
      await expect(encodeJwt({ header, payload, algorithm: 'HS256', secret: '' })).rejects.toThrow('The secret cannot be empty');
    });

    it('throws when the private key is not a PEM key', async () => {
      await expect(encodeJwt({ header, payload, algorithm: 'RS256', privateKeyPem: 'foo' })).rejects.toThrow('Invalid private key for RS256');
    });

    it('explains how to convert SEC1 EC keys', async () => {
      await expect(
        encodeJwt({ header, payload, algorithm: 'ES256', privateKeyPem: '-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----' }),
      ).rejects.toThrow('openssl pkcs8');
    });

    it.each(['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256', 'ES384', 'ES512'] as const)(
      'signs with %s a token verifiable with the public key',
      async (algorithm) => {
        const { privateKeyPem, publicKeyPem } = await generateKeyPair({ algorithm });
        const token = await encodeJwt({ header, payload, algorithm, privateKeyPem });

        expect(await verifyWithPublicKey({ token, algorithm, publicKeyPem })).toBe(true);
      },
    );

    it('accepts PKCS#1 RSA private keys', async () => {
      const { privateKeyPem, publicKeyPem } = await generateKeyPair({ algorithm: 'RS256' });
      const pkcs1Pem = pki.privateKeyToPem(pki.privateKeyFromPem(privateKeyPem));
      const token = await encodeJwt({ header, payload, algorithm: 'RS256', privateKeyPem: pkcs1Pem });

      expect(pkcs1Pem).toContain('BEGIN RSA PRIVATE KEY');
      expect(await verifyWithPublicKey({ token, algorithm: 'RS256', publicKeyPem })).toBe(true);
    });
  });
});

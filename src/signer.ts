import { type PrivateKey, ProtoWallet, PublicKey } from '@bsv/sdk';
import type { Brc42Protocol } from './derive.js';

export class SessionExpired extends Error {
  constructor() {
    super('SessionExpired');
    this.name = 'SessionExpired';
  }
}

export interface Signer {
  publicKey(): string;
  derivedPublicKey(protocolID: Brc42Protocol, keyID: string, counterparty?: string): string;
  sign(
    data: Uint8Array,
    protocolID?: Brc42Protocol,
    keyID?: string,
    counterparty?: string,
  ): Promise<Uint8Array>;
  encrypt(
    data: Uint8Array,
    protocolID: Brc42Protocol,
    keyID: string,
    counterparty: string,
  ): Promise<Uint8Array>;
  decrypt(
    data: Uint8Array,
    protocolID: Brc42Protocol,
    keyID: string,
    counterparty: string,
  ): Promise<Uint8Array>;
  ecdh(
    counterpartyPublicKey: string,
    protocolID: Brc42Protocol,
    keyID: string,
  ): Promise<Uint8Array>;
}

export function createSigner(
  privateKey: PrivateKey,
  session: { expiresAt: number },
  now: () => number = Date.now,
): Signer {
  const wallet = new ProtoWallet(privateKey);

  function checkSession(): void {
    if (now() > session.expiresAt) throw new SessionExpired();
  }

  function ownPublicKeyHex(): string {
    return privateKey.toPublicKey().encode(true, 'hex') as string;
  }

  return {
    publicKey(): string {
      checkSession();
      return ownPublicKeyHex();
    },

    derivedPublicKey(protocolID: Brc42Protocol, keyID: string, counterparty = 'self'): string {
      checkSession();
      return wallet.keyDeriver === undefined
        ? ownPublicKeyHex()
        : (wallet.keyDeriver
            .derivePublicKey(protocolID, keyID, counterparty)
            .encode(true, 'hex') as string);
    },

    async sign(
      data: Uint8Array,
      protocolID?: Brc42Protocol,
      keyID?: string,
      counterparty = 'self',
    ): Promise<Uint8Array> {
      checkSession();
      if (protocolID === undefined || keyID === undefined) {
        const signature = privateKey.sign(Array.from(data));
        return Uint8Array.from(signature.toDER() as number[]);
      }
      const result = await wallet.createSignature({
        protocolID,
        keyID,
        counterparty,
        data: Array.from(data),
      });
      return Uint8Array.from(result.signature);
    },

    async encrypt(
      data: Uint8Array,
      protocolID: Brc42Protocol,
      keyID: string,
      counterparty: string,
    ): Promise<Uint8Array> {
      checkSession();
      const result = await wallet.encrypt({
        protocolID,
        keyID,
        counterparty,
        plaintext: Array.from(data),
      });
      return Uint8Array.from(result.ciphertext);
    },

    async decrypt(
      data: Uint8Array,
      protocolID: Brc42Protocol,
      keyID: string,
      counterparty: string,
    ): Promise<Uint8Array> {
      checkSession();
      const result = await wallet.decrypt({
        protocolID,
        keyID,
        counterparty,
        ciphertext: Array.from(data),
      });
      return Uint8Array.from(result.plaintext);
    },

    async ecdh(
      counterpartyPublicKey: string,
      protocolID: Brc42Protocol,
      keyID: string,
    ): Promise<Uint8Array> {
      checkSession();
      if (wallet.keyDeriver === undefined) {
        const point = privateKey.deriveSharedSecret(PublicKey.fromString(counterpartyPublicKey));
        return Uint8Array.from((point.encode(true) as number[]).slice(1));
      }
      // BRC-42 symmetric key: identical on both sides for the same protocol and key id.
      const symmetric = wallet.keyDeriver.deriveSymmetricKey(
        protocolID,
        keyID,
        counterpartyPublicKey,
      );
      return Uint8Array.from(symmetric.toArray('be', 32) as number[]);
    },
  };
}

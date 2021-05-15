import { modPow } from "bigint-mod-arith";
import { SRPParameters } from "./parameters";
import {
  bigIntToArrayBuffer,
  generateRandomBigInt,
  hash,
  hashPadded,
  stringToArrayBuffer,
  arrayBufferToBigInt,
  hashBitCount,
} from "./utils";

/**
 * Default routines used for SRP calculation.
 *
 * These routines were implemented based on the Java Nimbus-SRP implementation.
 * This project can be found at https://bitbucket.org/connect2id/nimbus-srp
 * and the reference routine implementation at:
 * https://bitbucket.org/connect2id/nimbus-srp/src/c88fec8a6dcd46dacf1e031b52f9bffca902acf4/src/main/java/com/nimbusds/srp6/SRP6Routines.java
 */

export class SRPRoutines {
  constructor(public readonly parameters: SRPParameters) {}

  public hash(...as: ArrayBuffer[]): Promise<ArrayBuffer> {
    return hash(this.parameters, ...as);
  }

  public hashPadded(...as: ArrayBuffer[]): Promise<ArrayBuffer> {
    const targetLength = Math.trunc((this.parameters.NBits + 7) / 8);
    return hashPadded(this.parameters, targetLength, ...as);
  }

  public async computeK(): Promise<bigint> {
    return arrayBufferToBigInt(
      await this.hashPadded(
        bigIntToArrayBuffer(this.parameters.primeGroup.N),
        bigIntToArrayBuffer(this.parameters.primeGroup.g),
      ),
    );
  }

  public async generateRandomSalt(numBytes?: number): Promise<bigint> {
    const HBits = await hashBitCount(this.parameters);
    // Recommended salt bytes is > than Hash output bytes. We default to twice
    // the bytes used by the hash
    const saltBytes = numBytes || (2 * HBits) / 8;
    return generateRandomBigInt(saltBytes);
  }

  public async computeX(I: string, s: bigint, P: string): Promise<bigint> {
    return arrayBufferToBigInt(
      await this.hash(
        bigIntToArrayBuffer(s),
        await this.computeIdentityHash(I, P),
      ),
    );
  }

  public async computeXStep2(
    s: bigint,
    identityHash: ArrayBuffer,
  ): Promise<bigint> {
    return arrayBufferToBigInt(
      await this.hash(bigIntToArrayBuffer(s), identityHash),
    );
  }

  public async computeIdentityHash(_: string, P: string): Promise<ArrayBuffer> {
    return await this.hash(stringToArrayBuffer(P));
  }

  public computeVerifier(x: bigint): bigint {
    return modPow(
      this.parameters.primeGroup.g,
      x,
      this.parameters.primeGroup.N,
    );
  }

  public generatePrivateValue(): bigint {
    const numBits = Math.max(256, this.parameters.NBits);
    let bi: bigint;

    do {
      bi = generateRandomBigInt(numBits / 8) % this.parameters.primeGroup.N;
    } while (bi === BigInt(0));

    return bi;
  }

  public computeClientPublicValue(a: bigint): bigint {
    return modPow(
      this.parameters.primeGroup.g,
      a,
      this.parameters.primeGroup.N,
    );
  }

  public isValidPublicValue(value: bigint): boolean {
    return value % this.parameters.primeGroup.N !== BigInt(0);
  }

  public async computeU(A: bigint, B: bigint): Promise<bigint> {
    return arrayBufferToBigInt(
      await this.hashPadded(bigIntToArrayBuffer(A), bigIntToArrayBuffer(B)),
    );
  }

  public async computeClientEvidence(
    _I: string,
    _s: bigint,
    A: bigint,
    B: bigint,
    S: bigint,
  ): Promise<bigint> {
    return arrayBufferToBigInt(
      await this.hash(
        bigIntToArrayBuffer(A),
        bigIntToArrayBuffer(B),
        bigIntToArrayBuffer(S),
      ),
    );
  }

  public async computeServerEvidence(
    A: bigint,
    M1: bigint,
    S: bigint,
  ): Promise<bigint> {
    return arrayBufferToBigInt(
      await this.hash(
        bigIntToArrayBuffer(A),
        bigIntToArrayBuffer(M1),
        bigIntToArrayBuffer(S),
      ),
    );
  }

  public computeClientSessionKey(
    k: bigint,
    x: bigint,
    u: bigint,
    a: bigint,
    B: bigint,
  ): bigint {
    const exp = u * x + a;
    const tmp =
      modPow(this.parameters.primeGroup.g, x, this.parameters.primeGroup.N) * k;

    return modPow(B - tmp, exp, this.parameters.primeGroup.N);
  }
}

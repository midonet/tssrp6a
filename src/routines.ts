import bigInt, { BigInteger } from "big-integer";
import { hashFunctions } from "./cross-env-crypto";
import { knownPrimeGroups, PrimeGroup } from "./parameters";
import {
  arrayBufferToBigInt,
  bigIntToArrayBuffer,
  generateRandomBigInt,
  hash,
  hashBitCount,
  hashPadded,
  modPow,
  stringToArrayBuffer,
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
  public readonly NBits: number;

  constructor(
    public readonly primeGroup: PrimeGroup = knownPrimeGroups[2048],
    public readonly H = hashFunctions["SHA-512"],
  ) {
    this.NBits = this.primeGroup.N.toString(2).length;

    if (!H) {
      throw new Error("Hash function required");
    }
  }

  public hash(...as: ArrayBuffer[]): Promise<ArrayBuffer> {
    return hash(this.H, ...as);
  }

  public hashPadded(...as: ArrayBuffer[]): Promise<ArrayBuffer> {
    const targetLength = Math.trunc((this.NBits + 7) / 8);
    return hashPadded(this.H, targetLength, ...as);
  }

  public async computeK(): Promise<BigInteger> {
    return arrayBufferToBigInt(
      await this.hashPadded(
        bigIntToArrayBuffer(this.primeGroup.N),
        bigIntToArrayBuffer(this.primeGroup.g),
      ),
    );
  }

  public async generateRandomSalt(numBytes?: number): Promise<BigInteger> {
    const HBits = await hashBitCount(this.H);
    // Recommended salt bytes is > than Hash output bytes. We default to twice
    // the bytes used by the hash
    const saltBytes = numBytes || (2 * HBits) / 8;
    return generateRandomBigInt(saltBytes);
  }

  public async computeX(
    I: string,
    s: BigInteger,
    P: string,
  ): Promise<BigInteger> {
    return arrayBufferToBigInt(
      await this.hash(
        bigIntToArrayBuffer(s),
        await this.computeIdentityHash(I, P),
      ),
    );
  }

  public async computeXStep2(
    s: BigInteger,
    identityHash: ArrayBuffer,
  ): Promise<BigInteger> {
    return arrayBufferToBigInt(
      await this.hash(bigIntToArrayBuffer(s), identityHash),
    );
  }

  public async computeIdentityHash(_: string, P: string): Promise<ArrayBuffer> {
    return await this.hash(stringToArrayBuffer(P));
  }

  public computeVerifier(x: BigInteger): BigInteger {
    return modPow(this.primeGroup.g, x, this.primeGroup.N);
  }

  public generatePrivateValue(): BigInteger {
    const numBits = Math.max(256, this.NBits);
    let bi: BigInteger;

    do {
      bi = generateRandomBigInt(numBits / 8).mod(this.primeGroup.N);
    } while (bi.equals(bigInt("0")));

    return bi;
  }

  public computeClientPublicValue(a: BigInteger): BigInteger {
    return modPow(this.primeGroup.g, a, this.primeGroup.N);
  }

  public isValidPublicValue(value: BigInteger): boolean {
    return !value.mod(this.primeGroup.N).equals(bigInt("0"));
  }

  public async computeU(A: BigInteger, B: BigInteger): Promise<BigInteger> {
    return arrayBufferToBigInt(
      await this.hashPadded(bigIntToArrayBuffer(A), bigIntToArrayBuffer(B)),
    );
  }

  public async computeClientEvidence(
    _I: string,
    _s: BigInteger,
    A: BigInteger,
    B: BigInteger,
    S: BigInteger,
  ): Promise<BigInteger> {
    return arrayBufferToBigInt(
      await this.hash(
        bigIntToArrayBuffer(A),
        bigIntToArrayBuffer(B),
        bigIntToArrayBuffer(S),
      ),
    );
  }

  public async computeServerEvidence(
    A: BigInteger,
    M1: BigInteger,
    S: BigInteger,
  ): Promise<BigInteger> {
    return arrayBufferToBigInt(
      await this.hash(
        bigIntToArrayBuffer(A),
        bigIntToArrayBuffer(M1),
        bigIntToArrayBuffer(S),
      ),
    );
  }

  public computeClientSessionKey(
    k: BigInteger,
    x: BigInteger,
    u: BigInteger,
    a: BigInteger,
    B: BigInteger,
  ): BigInteger {
    const N = this.primeGroup.N;
    const exp = u.multiply(x).add(a);
    const tmp = modPow(this.primeGroup.g, x, N).multiply(k).mod(N);

    return modPow(B.add(N).subtract(tmp), exp, N);
  }
}

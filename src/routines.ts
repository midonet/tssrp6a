import bigInt, { BigInteger } from "big-integer";
import { SRPParameters } from "./parameters";
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
  constructor(public readonly parameters: SRPParameters) {}

  public hash(...as: ArrayBuffer[]): Promise<ArrayBuffer> {
    return hash(this.parameters, ...as);
  }

  public hashPadded(...as: ArrayBuffer[]): Promise<ArrayBuffer> {
    const targetLength = Math.trunc((this.parameters.NBits + 7) / 8);
    return hashPadded(this.parameters, targetLength, ...as);
  }

  public async computeK(): Promise<BigInteger> {
    return arrayBufferToBigInt(
      await this.hashPadded(
        bigIntToArrayBuffer(this.parameters.primeGroup.N),
        bigIntToArrayBuffer(this.parameters.primeGroup.g),
      ),
    );
  }

  public async generateRandomSalt(numBytes?: number): Promise<BigInteger> {
    const HBits = await hashBitCount(this.parameters);
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
    return modPow(
      this.parameters.primeGroup.g,
      x,
      this.parameters.primeGroup.N,
    );
  }

  public generatePrivateValue(): BigInteger {
    const numBits = Math.max(256, this.parameters.NBits);
    let bi: BigInteger;

    do {
      bi = generateRandomBigInt(numBits / 8).mod(this.parameters.primeGroup.N);
    } while (bi.equals(bigInt("0")));

    return bi;
  }

  public computeClientPublicValue(a: BigInteger): BigInteger {
    return modPow(
      this.parameters.primeGroup.g,
      a,
      this.parameters.primeGroup.N,
    );
  }

  public isValidPublicValue(value: BigInteger): boolean {
    return !value.mod(this.parameters.primeGroup.N).equals(bigInt("0"));
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
    const N = this.parameters.primeGroup.N;
    const exp = u.multiply(x).add(a);
    const tmp = modPow(this.parameters.primeGroup.g, x, N).multiply(k).mod(N);

    return modPow(B.add(N).subtract(tmp), exp, N);
  }
}

import { modPow } from "bigint-mod-arith";
import { SRPParameters } from "./parameters";
import {
  bigIntToArrayBuffer,
  generateRandomBigInt,
  hash,
  hashPadded,
  HashWordArray,
  stringToArrayBuffer,
  arrayBufferToBigInt,
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

  public hash(...as: HashWordArray[]): HashWordArray {
    return hash(this.parameters, ...as);
  }

  public hashPadded(...as: HashWordArray[]): HashWordArray {
    const targetLength = Math.trunc((this.parameters.NBits + 7) / 8);
    return hashPadded(this.parameters, targetLength, ...as);
  }

  public computeK(): bigint {
    return arrayBufferToBigInt(
      this.hashPadded(
        bigIntToArrayBuffer(this.parameters.N),
        bigIntToArrayBuffer(this.parameters.g),
      ),
    );
  }

  public generateRandomSalt(numBytes?: number): bigint {
    // Recommended salt bytes is > than Hash output bytes. We default to twice
    // the bytes used by the hash
    const saltBytes = numBytes || (2 * this.parameters.HBits) / 8;
    return generateRandomBigInt(saltBytes);
  }

  public computeX(I: string, s: bigint, P: string): bigint {
    return arrayBufferToBigInt(
      this.hash(bigIntToArrayBuffer(s), this.computeIdentityHash(I, P)),
    );
  }

  public computeXStep2(s: bigint, identityHash: HashWordArray): bigint {
    return arrayBufferToBigInt(this.hash(bigIntToArrayBuffer(s), identityHash));
  }

  public computeIdentityHash(_: string, P: string): HashWordArray {
    return this.hash(stringToArrayBuffer(P));
  }

  public computeVerifier(x: bigint): bigint {
    return modPow(this.parameters.g, x, this.parameters.N);
  }

  public generatePrivateValue(): bigint {
    const numBits = Math.max(256, this.parameters.NBits);
    let bi: bigint;

    do {
      bi = generateRandomBigInt(numBits / 8) % this.parameters.N;
    } while (bi === BigInt(0));

    return bi;
  }

  public computeClientPublicValue(a: bigint): bigint {
    return modPow(this.parameters.g, a, this.parameters.N);
  }

  public isValidPublicValue(value: bigint): boolean {
    return value % this.parameters.N !== BigInt(0);
  }

  public computeU(A: bigint, B: bigint): bigint {
    return arrayBufferToBigInt(
      this.hashPadded(bigIntToArrayBuffer(A), bigIntToArrayBuffer(B)),
    );
  }

  public computeClientEvidence(
    _I: string,
    _s: bigint,
    A: bigint,
    B: bigint,
    S: bigint,
  ): bigint {
    return arrayBufferToBigInt(
      this.hash(
        bigIntToArrayBuffer(A),
        bigIntToArrayBuffer(B),
        bigIntToArrayBuffer(S),
      ),
    );
  }

  public computeServerEvidence(A: bigint, M1: bigint, S: bigint): bigint {
    return arrayBufferToBigInt(
      this.hash(
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
    const tmp = modPow(this.parameters.g, x, this.parameters.N) * k;

    return modPow(B - tmp, exp, this.parameters.N);
  }
}

import { modPow } from "bigint-mod-arith";
import { SRPParameters } from "./parameters";
import { generateRandomBigInt } from "./utils";

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

  public computeK(): bigint {
    return this.parameters.hashPadded(this.parameters.N, this.parameters.g);
  }

  public generateRandomSalt(numBytes?: number): bigint {
    // Recommended salt bytes is > than Hash output bytes. We default to twice
    // the bytes used by the hash
    const saltBytes = numBytes || (2 * this.parameters.HBits) / 8;
    return generateRandomBigInt(saltBytes);
  }

  public computeX(I: string, s: bigint, P: string): bigint {
    const identityHash: any = this.computeIdentityHash(I, P);
    return this.parameters.hash(s, identityHash);
  }

  public computeXStep2(s: bigint, identityHash: unknown): bigint {
    return this.parameters.hash(s, identityHash);
  }

  public computeIdentityHash(_: string, P: string): unknown {
    return this.parameters.hashValue(P);
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
    return this.parameters.hashPadded(A, B);
  }

  public computeClientEvidence(
    _I: string,
    _s: bigint,
    A: bigint,
    B: bigint,
    S: bigint,
  ): bigint {
    return this.parameters.hash(A, B, S);
  }

  public computeServerEvidence(A: bigint, M1: bigint, S: bigint): bigint {
    return this.parameters.hash(A, M1, S);
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

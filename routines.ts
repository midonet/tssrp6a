import { BigInteger } from "jsbn";

import { SRPParameters } from "./parameters";
import {
  bigIntegerToWordArray,
  generateRandomBigInteger,
  hash,
  hashPadded,
  HashWordArray,
  stringToWordArray,
  wordArrayToBigInteger,
} from "./utils";

// tslint:disable:max-line-length
/**
 * Default routines used for SRP calculation.
 *
 * These routines were implemented based on the Java Nimbus-SRP implementation.
 * This project can be found at https://bitbucket.org/connect2id/nimbus-srp
 * and the reference routine implementation at:
 * https://bitbucket.org/connect2id/nimbus-srp/src/c88fec8a6dcd46dacf1e031b52f9bffca902acf4/src/main/java/com/nimbusds/srp6/SRP6Routines.java
 */
// tslint:enable:max-line-length

// tslint:disable:variable-name
export class SRPRoutines {
  private _parameters: SRPParameters;

  constructor(parameters: SRPParameters) {
    this._parameters = parameters;
  }

  get parameters(): SRPParameters {
    return this._parameters;
  }

  public hash(...as: HashWordArray[]): HashWordArray {
    return hash(this.parameters, ...as);
  }

  public hashPadded(...as: HashWordArray[]): HashWordArray {
    const targetLength = Math.trunc((this.parameters.NBits + 7) / 8);
    return hashPadded(this.parameters, targetLength, ...as);
  }

  public hashAsBase64(key: BigInteger): BigInteger {
    return wordArrayToBigInteger(this.hash(bigIntegerToWordArray(key)));
  }

  public computeK(): BigInteger {
    return wordArrayToBigInteger(
      this.hashPadded(
        bigIntegerToWordArray(this.parameters.N),
        bigIntegerToWordArray(this.parameters.g),
      ),
    );
  }

  public generateRandomSalt(numBytes?: number): BigInteger {
    // Recommended salt bytes is > than Hash output bytes. We default to twice
    // the bytes used by the hash
    const saltBytes = numBytes || (2 * this.parameters.HBits) / 8;
    return generateRandomBigInteger(saltBytes);
  }

  public computeX(I: string, s: BigInteger, P: string): BigInteger {
    return wordArrayToBigInteger(
      this.hash(bigIntegerToWordArray(s), this.computeIdentityHash(I, P)),
    );
  }

  public computeXStep2(s: BigInteger, identityHash: HashWordArray): BigInteger {
    return wordArrayToBigInteger(
      this.hash(bigIntegerToWordArray(s), identityHash),
    );
  }

  public computeIdentityHash(_: string, P: string): HashWordArray {
    return this.hash(stringToWordArray(P));
  }

  public computeVerifier(x: BigInteger): BigInteger {
    return this.parameters.g.modPow(x, this.parameters.N);
  }

  public generatePrivateValue(): BigInteger {
    const numBits = Math.max(256, this.parameters.NBits);
    let bi: BigInteger;

    do {
      bi = generateRandomBigInteger(numBits / 8);
    } while (bi.signum() === 0);

    return bi;
  }

  public computeClientPublicValue(a: BigInteger): BigInteger {
    return this.parameters.g.modPow(a, this.parameters.N);
  }

  public isValidPublicValue(value: BigInteger): boolean {
    return value.mod(this.parameters.N).signum() !== 0;
  }

  public computeU(A: BigInteger, B: BigInteger): BigInteger {
    return wordArrayToBigInteger(
      this.hashPadded(bigIntegerToWordArray(A), bigIntegerToWordArray(B)),
    );
  }

  public computeClientEvidence(
    _I: string,
    _s: BigInteger,
    A: BigInteger,
    B: BigInteger,
    S: BigInteger,
  ): BigInteger {
    return wordArrayToBigInteger(
      this.hash(
        bigIntegerToWordArray(A),
        bigIntegerToWordArray(B),
        bigIntegerToWordArray(S),
      ),
    );
  }

  public computeServerEvidence(
    A: BigInteger,
    M1: BigInteger,
    S: BigInteger,
  ): BigInteger {
    return wordArrayToBigInteger(
      this.hash(
        bigIntegerToWordArray(A),
        bigIntegerToWordArray(M1),
        bigIntegerToWordArray(S),
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
    const exp = u.multiply(x).add(a);
    const tmp = this.parameters.g.modPow(x, this.parameters.N).multiply(k);

    return B.subtract(tmp).modPow(exp, this.parameters.N);
  }
}

export type SRPRoutinesFactory = (params: SRPParameters) => SRPRoutines;

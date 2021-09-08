import { SRPParameters } from "./parameters";
/**
 * Default routines used for SRP calculation.
 *
 * These routines were implemented based on the Java Nimbus-SRP implementation.
 * This project can be found at https://bitbucket.org/connect2id/nimbus-srp
 * and the reference routine implementation at:
 * https://bitbucket.org/connect2id/nimbus-srp/src/c88fec8a6dcd46dacf1e031b52f9bffca902acf4/src/main/java/com/nimbusds/srp6/SRP6Routines.java
 */
export declare class SRPRoutines {
    readonly parameters: SRPParameters;
    constructor(parameters: SRPParameters);
    hash(...as: ArrayBuffer[]): Promise<ArrayBuffer>;
    hashPadded(...as: ArrayBuffer[]): Promise<ArrayBuffer>;
    computeK(): Promise<bigint>;
    generateRandomSalt(numBytes?: number): Promise<bigint>;
    computeX(I: string, s: bigint, P: string): Promise<bigint>;
    computeXStep2(s: bigint, identityHash: ArrayBuffer): Promise<bigint>;
    computeIdentityHash(_: string, P: string): Promise<ArrayBuffer>;
    computeVerifier(x: bigint): bigint;
    generatePrivateValue(): bigint;
    computeClientPublicValue(a: bigint): bigint;
    isValidPublicValue(value: bigint): boolean;
    computeU(A: bigint, B: bigint): Promise<bigint>;
    computeClientEvidence(_I: string, _s: bigint, A: bigint, B: bigint, S: bigint): Promise<bigint>;
    computeServerEvidence(A: bigint, M1: bigint, S: bigint): Promise<bigint>;
    computeClientSessionKey(k: bigint, x: bigint, u: bigint, a: bigint, B: bigint): bigint;
}

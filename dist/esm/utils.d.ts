import { SRPParameters } from "./parameters";
import { SRPRoutines } from "./routines";
export declare const bigIntToArrayBuffer: (n: bigint) => ArrayBuffer;
export declare const arrayBufferToBigInt: (arrayBuffer: ArrayBuffer) => bigint;
/**
 * Convert some string into ArrayBuffer.
 * @param str Any UTF8 string, like a username, email, or password
 */
export declare function stringToArrayBuffer(str: string): ArrayBuffer;
/**
 * Left pad ArrayBuffer with zeroes.
 * @param arrayBuffer - ArrayBuffer to pad
 * @param targetLength Length of the target array in bytes.
 * @returns Padded array or original array if targetLength is less than original
 *          array length.
 */
export declare const padStartArrayBuffer: (arrayBuffer: ArrayBuffer, targetLength: number) => ArrayBuffer;
export declare function hash(parameters: SRPParameters, ...arrays: ArrayBuffer[]): Promise<ArrayBuffer>;
export declare function hashPadded(parameters: SRPParameters, targetLen: number, ...arrays: ArrayBuffer[]): Promise<ArrayBuffer>;
/**
 * Generates random string of ASCII characters using crypto secure random generator.
 * @param characterCount The length of the result string.
 * @return The string.
 */
export declare function generateRandomString(characterCount?: number): string;
export declare function generateRandomBigInt(numBytes?: number): bigint;
export declare function createVerifier(routines: SRPRoutines, I: string, s: bigint, P: string): Promise<bigint>;
export interface IVerifierAndSalt {
    v: bigint;
    s: bigint;
}
export declare function createVerifierAndSalt(routines: SRPRoutines, I: string, P: string, sBytes?: number): Promise<IVerifierAndSalt>;
export declare const hashBitCount: (parameters: SRPParameters) => Promise<number>;
/**
 * Calculates (x**pow) % mod
 * @param x base, non negative big int.
 * @param pow power, non negative power.
 * @param mod modulo, positive modulo for division.
 */
export declare function modPow(x: bigint, pow: bigint, mod: bigint): bigint;

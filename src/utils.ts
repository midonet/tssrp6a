import * as CryptoJS from "crypto-js";

import { SRPParameters } from "./parameters";
import { SRPRoutines } from "./routines";

export type HashWordArray = CryptoJS.LibWordArray;

export const bigIntegerToWordArray = (n: bigint): HashWordArray =>
  CryptoJS.enc.Hex.parse(evenLengthHex(n.toString(16)));

export const wordArrayToBigInt = (words: HashWordArray): bigint =>
  BigInt(`0x${CryptoJS.enc.Hex.stringify(words)}`);

/**
 * Convert some string into HashWordArray.
 * @param str Any UTF8 string, like a username, email, or password
 */
export function stringToWordArray(str: string): HashWordArray {
  return CryptoJS.enc.Utf8.parse(str);
}

/**
 * Left pad HashWordArray with zeroes.
 * @param targetLength Length of the target array in bytes.
 * @returns Padded array or original array if targetLength is less than original
 *          array length.
 */
export const padWordArray = (
  words: HashWordArray,
  targetLength: number,
): HashWordArray => {
  let result: HashWordArray = words;
  if (targetLength > words.sigBytes) {
    const resultWords: number[] = new Array(ceilDiv4(targetLength)).fill(0);
    result = createHashWordArray(resultWords, targetLength);
    for (
      let dest = targetLength - words.sigBytes, src = 0;
      src < words.sigBytes;
      ++src, ++dest
    ) {
      setByte(result, dest, getByte(words, src));
    }
  }
  return result;
};

export function hash(
  parameters: SRPParameters,
  ...arrays: HashWordArray[]
): HashWordArray {
  parameters.H.reset();
  arrays.forEach((hwa) => parameters.H.update(hwa));
  return parameters.H.finalize();
}

export function hashPadded(
  parameters: SRPParameters,
  targetLen: number,
  ...arrays: HashWordArray[]
): HashWordArray {
  const arraysPadded = arrays.map((hwa) => padWordArray(hwa, targetLen));
  return hash(parameters, ...arraysPadded);
}

/**
 * Generates random string of ASCII characters using crypto secure random generator.
 * @param characterCount The length of the result string.
 * @return The string.
 */
export function generateRandomString(characterCount: number = 10): string {
  const randomArray = generateRandom(characterCount);
  for (let i = 0; i < randomArray.sigBytes; ++i) {
    let asciiChar = getByte(randomArray, i) & 0x7f;
    if (asciiChar < 32) {
      asciiChar |= 32;
    }
    if (asciiChar === 0x7f) {
      asciiChar = 0x7e;
    }
    setByte(randomArray, i, asciiChar);
  }
  return CryptoJS.enc.Utf8.stringify(randomArray);
}

export function generateRandomBigInt(numBytes: number = 16): bigint {
  return wordArrayToBigInt(generateRandom(numBytes));
}

export function createVerifier(
  routines: SRPRoutines,
  I: string,
  s: bigint,
  P: string,
): bigint {
  if (!I || !I.trim()) {
    throw new Error("Identity (I) must not be null or empty.");
  }

  if (!s) {
    throw new Error("Salt (s) must not be null.");
  }

  if (!P) {
    throw new Error("Password (P) must not be null");
  }

  const x = routines.computeX(I, s, P);

  return routines.computeVerifier(x);
}

export interface IVerifierAndSalt {
  v: bigint;
  s: bigint;
}

export function createVerifierAndSalt(
  routines: SRPRoutines,
  I: string,
  P: string,
  sBytes?: number,
): IVerifierAndSalt {
  const s = routines.generateRandomSalt(sBytes);

  return {
    s,
    v: createVerifier(routines, I, s, P),
  };
}

export const hashBitCount = (parameters: SRPParameters): number =>
  hash(parameters, bigIntegerToWordArray(BigInt(1))).sigBytes << 3;

// TODO: remove when constructor is exported in @types/crypto-js
export function createHashWordArray(
  words: number[],
  sigBytes: number,
): HashWordArray {
  const result: HashWordArray = CryptoJS.lib.WordArray.create(words);
  result.sigBytes = sigBytes;
  return result;
}

function evenLengthHex(hex: string): string {
  if (hex.length % 2 === 1) {
    return `0${hex}`;
  } else {
    return hex;
  }
}

function ceilDiv4(x: number) {
  return (x + 3) >>> 2;
}

/**
 * Return the number of bits the byte should be shifted to occupy given position in 4 bytes integer.
 * @param byteNum The number of byte in big endian order. Can be only 0, 1, 2 or 3
 */
function byteShift(byteNum: number): number {
  return (3 - byteNum) << 3;
}

function getByte(array: HashWordArray, idx: number): number {
  return (array.words[idx >>> 2] >>> byteShift(idx & 3)) & 0xff;
}

function setByte(array: HashWordArray, idx: number, byteValue: number): void {
  array.words[idx >>> 2] &= ~(0xff << byteShift(idx & 3));
  array.words[idx >>> 2] |= (byteValue & 0xff) << byteShift(idx & 3);
}

const generateRandom = (numBytes: number): HashWordArray => {
  // TODO: fix type of this function in @types/crypto-js
  return CryptoJS.lib.WordArray.random(numBytes) as any as HashWordArray;
};

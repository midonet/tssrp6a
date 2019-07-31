import * as CryptoJS from "crypto-js";
import { BigInteger } from "jsbn";

import { SRPConfig } from "./config";
import { SRPParameters } from "./parameters";

const identity = <T>(a: T) => a;

export type LibWordArray = CryptoJS.LibWordArray;

export const bigIntegerToWordArray = (n: BigInteger): LibWordArray =>
  CryptoJS.enc.Hex.parse(evenLengthHex(n.toString(16)));

export const wordArrayToBigInteger = (words: LibWordArray): BigInteger =>
  new BigInteger(CryptoJS.enc.Hex.stringify(words), 16);

export function evenLengthHex(hex: string): string {
  if (hex.length % 2 === 1) {
    return `0${hex}`;
  } else {
    return hex;
  }
}

/**
 * Convert some string into LibWordArray, suitable for hashing.
 * @param str Any string, like a username, email, or password
 */
export function stringToWordArray(str: string): LibWordArray {
  const bytes = new Uint8Array(str.length);
  for (let i = 0; i < str.length; ++i) {
    bytes[i] = str.charCodeAt(i);
  }

  const hexString = Array.from(bytes)
    .map((b) => {
      return evenLengthHex(b.toString(16));
    })
    .join("");

  return CryptoJS.enc.Hex.parse(hexString);
}

const padWordArray = (targetLength: number) => (
  words: LibWordArray,
): LibWordArray => {
  const hexString = CryptoJS.enc.Hex.stringify(words);
  const currentByteLength = hexString.length / 2;
  const byteLengthDiff = targetLength - currentByteLength;

  return CryptoJS.enc.Hex.parse(
    byteLengthDiff > 0
      ? "00".repeat(byteLengthDiff) + hexString
      : hexString.substring(-byteLengthDiff),
  );
};

export function hash(
  parameters: SRPParameters,
  ...as: LibWordArray[]
): LibWordArray {
  return hashPadded(parameters, null, ...as);
}

export function hashPadded(
  parameters: SRPParameters,
  targetLen: number | null,
  ...as: LibWordArray[]
): LibWordArray {
  parameters.H.reset();

  as.map(targetLen !== null ? padWordArray(targetLen) : identity).forEach(
    (wa: LibWordArray) => parameters.H.update(wa),
  );

  return parameters.H.finalize();
}

const generateRandom = (numBytes: number = 16): LibWordArray => {
  return CryptoJS.lib.WordArray.random(numBytes) as any;
};

export const generateRandomString = (characterCount: number = 10): string =>
  CryptoJS.enc.Hex.stringify(generateRandom(characterCount / 2));

export function generateRandomBigInteger(numBytes: number = 16): BigInteger {
  return wordArrayToBigInteger(generateRandom(numBytes));
}

export function createVerifier(
  config: SRPConfig,
  I: string,
  s: BigInteger,
  P: string,
): BigInteger {
  if (!I || !I.trim()) {
    throw new Error("Identity (I) must not be null or empty.");
  }

  if (!s) {
    throw new Error("Salt (s) must not be null.");
  }

  if (!P) {
    throw new Error("Password (P) must not be null");
  }

  const routines = config.routines;

  const x = routines.computeX(I, s, P);

  return routines.computeVerifier(x);
}

export interface IVerifierAndSalt {
  v: BigInteger;
  s: BigInteger;
}

export function createVerifierAndSalt(
  config: SRPConfig,
  I: string,
  P: string,
  sBytes?: number,
): IVerifierAndSalt {
  const s = config.routines.generateRandomSalt(sBytes);

  return {
    s,
    v: createVerifier(config, I, s, P),
  };
}

export const hashBitCount = (parameters: SRPParameters): number =>
  wordArrayToBigInteger(
    hash(parameters, bigIntegerToWordArray(BigInteger.ONE)),
  ).bitCount();

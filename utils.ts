import * as CryptoJS from "crypto-js";
import { BigInteger } from "jsbn";

import { SRPConfig } from "./config";
import { SRPParameters } from "./parameters";

export type Base64String = string;

const identity = <T>(a: T) => a;

export const bigIntegerToWordArray = (n: BigInteger): CryptoJS.WordArray =>
  CryptoJS.enc.Hex.parse(evenLengthHex(n.toString(16)));

export const wordArrayToBigInteger = (words: CryptoJS.WordArray): BigInteger =>
  new BigInteger(CryptoJS.enc.Hex.stringify(words), 16);

export const wordArrayTobase64 = (words: CryptoJS.WordArray): Base64String =>
  CryptoJS.enc.Base64.stringify(words);

export const base64ToWordArray = (base64: Base64String): CryptoJS.WordArray =>
  CryptoJS.enc.Base64.parse(base64);

export const bigIntegerToBase64 = (n: BigInteger): Base64String =>
  wordArrayTobase64(bigIntegerToWordArray(n));

export const base64ToBigInteger = (base64: Base64String): BigInteger => {
  return wordArrayToBigInteger(base64ToWordArray(base64));
};

export function evenLengthHex(hex: string): string {
  if (hex.length % 2 === 1) {
    return `0${hex}`;
  } else {
    return hex;
  }
}

/**
 * Convert some string into CryptoJS.WordArray, suitable for hashing.
 * @param str Any string, like a username, email, or password
 */
export function stringToBigInteger(str: string): CryptoJS.WordArray {
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
  words: CryptoJS.WordArray,
): CryptoJS.WordArray => {
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
  ...as: CryptoJS.WordArray[]
): CryptoJS.WordArray {
  return hashPadded(parameters, null, ...as);
}

export function hashPadded(
  parameters: SRPParameters,
  targetLen: number | null,
  ...as: CryptoJS.WordArray[]
): CryptoJS.WordArray {
  parameters.H.reset();

  as.map(targetLen !== null ? padWordArray(targetLen) : identity).forEach(
    (wa: CryptoJS.WordArray) => parameters.H.update(wa),
  );

  return parameters.H.finalize();
}

const generateRandom = (numBytes: number = 16): CryptoJS.WordArray => {
  return CryptoJS.lib.WordArray.random(numBytes) as any;
};

export function generateRandomBase64(numBytes: number = 16): Base64String {
  return bigIntegerToBase64(generateRandomBigInteger(numBytes));
}

export const generateRandomString = (characterCount: number = 10): string =>
  CryptoJS.enc.Hex.stringify(generateRandom(characterCount / 2));

export function generateRandomBigInteger(numBytes: number = 16): BigInteger {
  return wordArrayToBigInteger(generateRandom(numBytes));
}

export function createVerifier(
  config: SRPConfig,
  I: string,
  s: Base64String,
  P: string,
): Base64String {
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

  const x = routines.computeX(I, base64ToBigInteger(s), P);

  return bigIntegerToBase64(routines.computeVerifier(x));
}

export interface IVerifierAndSalt {
  v: Base64String;
  s: Base64String;
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
  wordArrayToBigInteger(hash(parameters, base64ToWordArray("Cg=="))).bitCount();

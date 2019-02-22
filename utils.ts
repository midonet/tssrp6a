import * as CryptoJS from "crypto-js";
import { BigInteger } from "jsbn";

import { SRPConfig } from "./config";
import { SRPParameters } from "./parameters";

const WordArray = CryptoJS.lib.WordArray;
const Hex = CryptoJS.enc.Hex;

export type ByteArray = Uint8Array;
export type HexString = string;

export function evenLengthHex(hex: HexString): HexString {
  if (hex.length % 2 === 1) {
    return `0${hex}`;
  } else {
    return hex;
  }
}

export function bytesToHex(bytes: ByteArray): string {
  return Array.from(bytes).map((b) => {
    return evenLengthHex(b.toString(16));
  }).join("");
}

export function hexToBytes(hexString: string): ByteArray {
  const hexByteLength = hexString.length / 2;

  const byteArray = new Uint8Array(hexByteLength);

  for (let i = 0, j = 0; i < hexString.length; i += 2, j += 1) {
    byteArray[j] = parseInt(hexString.substring(i, i + 2), 16);
  }

  return byteArray;
}

export function hexToBigInteger(hexString: string): BigInteger {
  return new BigInteger(hexString, 16);
}

export function hexToWordArray(hexString: string): CryptoJS.WordArray {
  return Hex.parse(hexString);
}

export function bigIntegerToHex(n: BigInteger): string {
  return evenLengthHex(n.toString(16));
}

export function utf8ToBytes(str: string): ByteArray {
  const bytes = new Uint8Array(str.length);

  for (let i = 0; i < str.length; ++i) {
    bytes[i] = str.charCodeAt(i);
  }

  return bytes;
}

export function utf8ToHex(str: string): HexString {
  return bytesToHex(utf8ToBytes(str));
}

export function wordArrayToHex(array: CryptoJS.WordArray): string {
  return Hex.stringify(array);
}

export function hexLeftPad(hexString: string, targetLength: number): string {
  const currentByteLength = hexString.length / 2;
  const byteLengthDiff = targetLength - currentByteLength;

  if (byteLengthDiff > 0) {
    return "00".repeat(byteLengthDiff) + hexString;
  } else {
    return hexString.substring(-byteLengthDiff);
  }
}

export function anyToHexString(a: any): HexString {
  if (typeof a === "string") {
    return a;
  } else if (a instanceof BigInteger) {
    return bigIntegerToHex(a);
  } else if (a instanceof Uint8Array) {
    return bytesToHex(a);
  } else {
    throw new Error(`Don"t know how to convert ${a} to hex string`);
  }
}

export function hash(parameters: SRPParameters, ...as: any[]): HexString {
  parameters.H.reset();

  as.map((a) => anyToHexString(a))
    .map((hs: HexString) => hexToWordArray(hs))
    .forEach((wa: CryptoJS.WordArray) => parameters.H.update(wa));

  return wordArrayToHex(parameters.H.finalize());
}

export function hashPadded(parameters: SRPParameters,
                           targetLen: number,
                           ...as: any[]): HexString {
  return hash(parameters, ...as.map((a) =>
    hexLeftPad(anyToHexString(a), targetLen)));
}

export function generateRandomHex(numBytes: number = 16): HexString {
  return wordArrayToHex(WordArray.random(numBytes) as any);
}

export function generateRandomBigInteger(numBytes: number = 16): BigInteger {
  return new BigInteger(numBytes * 8, {
    nextBytes(dest: number[]): void {
      const bytes = hexToBytes(generateRandomHex(dest.length));
      // eslint-disable-next-line no-param-reassign
      bytes.forEach((b, i) => { dest[i] = b; });
    },
  });
}

export function createVerifierHexSalt(config: SRPConfig, I: string,
                                      s: HexString,
                                      P: string): HexString {
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

  const x = routines.computeX(I, evenLengthHex(s), utf8ToHex(P));

  return bigIntegerToHex(routines.computeVerifier(x));
}

export function createVerifier(config: SRPConfig, I: string, s: string,
                               P: string): HexString {
  return createVerifierHexSalt(config, I, utf8ToHex(s), P);
}

export interface IVerifierAndSalt {
  v: HexString;
  s: HexString;
}

export function createVerifierAndSalt(config: SRPConfig,
                                      I: string,
                                      P: string,
                                      sBytes?: number): IVerifierAndSalt {
  const s = config.routines.generateRandomSalt(sBytes);

  return {
    s,
    v: createVerifierHexSalt(config, I, s, P),
  };
}

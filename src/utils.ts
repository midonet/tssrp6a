import bigInt, { BigInteger } from "big-integer";
import { HashFunction, randomBytes } from "./cross-env-crypto";
import { SRPRoutines } from "./routines";

export const bigIntToArrayBuffer = (n: BigInteger): ArrayBuffer => {
  const hex = n.toString(16);
  const arrayBuffer = new ArrayBuffer(Math.ceil(hex.length / 2));
  const u8 = new Uint8Array(arrayBuffer);
  let offset = 0;
  // handle toString(16) not padding
  if (hex.length % 2 !== 0) {
    u8[0] = parseInt(hex[0], 16);
    offset = 1;
  }
  for (let i = 0; i < arrayBuffer.byteLength; i++) {
    u8[i + offset] = parseInt(
      hex.slice(2 * i + offset, 2 * i + 2 + offset),
      16,
    );
  }
  return arrayBuffer;
};

export const arrayBufferToBigInt = (arrayBuffer: ArrayBuffer): BigInteger => {
  const hex: string[] = [];
  // we can't use map here because map will return Uint8Array which will screw up the parsing below
  new Uint8Array(arrayBuffer).forEach((i) => {
    hex.push(("0" + i.toString(16)).slice(-2)); // i.toString(16) will transform 01 to 1, so we add it back on and slice takes the last two chars
  });
  return bigInt(hex.join(""), 16);
};

/**
 * Convert some string into ArrayBuffer.
 * @param str Any UTF8 string, like a username, email, or password
 */
export const stringToArrayBuffer = (str: string): ArrayBuffer =>
  new TextEncoder().encode(str).buffer;

/**
 * Left pad ArrayBuffer with zeroes.
 * @param arrayBuffer - ArrayBuffer to pad
 * @param targetLength Length of the target array in bytes.
 * @returns Padded array or original array if targetLength is less than original
 *          array length.
 */
export const padStartArrayBuffer = (
  arrayBuffer: ArrayBuffer,
  targetLength: number,
): ArrayBuffer => {
  const u8 = new Uint8Array(arrayBuffer);
  if (u8.length < targetLength) {
    const tmp = new Uint8Array(targetLength);
    tmp.fill(0, 0, targetLength - u8.length);
    tmp.set(u8, targetLength - u8.length);
    return tmp;
  }
  return u8;
};

export const hash = (
  H: HashFunction,
  ...arrays: ArrayBuffer[]
): Promise<ArrayBuffer> => {
  const length = arrays.reduce((p, c) => p + c.byteLength, 0);
  const target = new Uint8Array(length);
  for (let offset = 0, i = 0; i < arrays.length; i++) {
    target.set(new Uint8Array(arrays[i]), offset);
    offset += arrays[i].byteLength;
  }
  return H(target);
};

export const hashPadded = (
  H: HashFunction,
  targetLen: number,
  ...arrays: ArrayBuffer[]
): Promise<ArrayBuffer> => {
  const arraysPadded = arrays.map((arrayBuffer) =>
    padStartArrayBuffer(arrayBuffer, targetLen),
  );
  return hash(H, ...arraysPadded);
};

/**
 * Generates random string of ASCII characters using crypto secure random generator.
 * @param characterCount The length of the result string.
 * @return The string.
 */
export const generateRandomString = (characterCount: number = 10) => {
  const u8 = new Uint8Array(Math.ceil(Math.ceil(characterCount / 2))); // each byte has 2 hex digits
  randomBytes(u8);
  return u8
    .reduce((str, i) => {
      const hex = i.toString(16).toString();
      if (hex.length === 1) {
        return str + "0" + hex;
      }
      return str + hex;
    }, "")
    .slice(0, characterCount); // so we don't go over when characterCount is odd
};

export const generateRandomBigInt = (numBytes: number = 16): BigInteger =>
  arrayBufferToBigInt(generateRandom(numBytes));

export const createVerifier = async (
  routines: SRPRoutines,
  I: string,
  s: BigInteger,
  P: string,
): Promise<BigInteger> => {
  if (!I || !I.trim()) {
    throw new Error("Identity (I) must not be null or empty.");
  }

  if (!s) {
    throw new Error("Salt (s) must not be null.");
  }

  if (!P) {
    throw new Error("Password (P) must not be null");
  }

  const x = await routines.computeX(I, s, P);

  return routines.computeVerifier(x);
};

export type IVerifierAndSalt = {
  v: BigInteger;
  s: BigInteger;
};

export const createVerifierAndSalt = async (
  routines: SRPRoutines,
  I: string,
  P: string,
  sBytes?: number,
): Promise<IVerifierAndSalt> => {
  const s = await routines.generateRandomSalt(sBytes);

  return {
    s,
    v: await createVerifier(routines, I, s, P),
  };
};

export const hashBitCount = async (H: HashFunction): Promise<number> =>
  (await hash(H, bigIntToArrayBuffer(bigInt("1")))).byteLength * 8;

const generateRandom = (numBytes: number): ArrayBuffer => {
  const u8 = new Uint8Array(numBytes);
  randomBytes(u8);
  return u8.buffer;
};
